# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'minitest/autorun'
require 'timeout'
require 'tmpdir'

require_relative 'fake_hub'

# Auth v2: the hub's proof, its pin and one token per connect (protocol.md §2).
class TestAuth < Minitest::Test
  HUB_KEY = FakeHub::HUB_KEY
  VECTORS = FakeHub::VECTORS

  def setup
    @dir = Dir.mktmpdir('hubauth-rb')
    HubServiceRB::Keychain.key_path = File.join(@dir, 'auth')
    FakeHub.start
    FakeHub.reset
  end

  def teardown
    @service&.stop
    HubServiceRB::Keychain.key_path = nil
    FileUtils.remove_entry(@dir)
  end

  def verify(token, hub_key = HUB_KEY)
    _, pub, sig, expiry, nonce = token.split('.')
    key = Ed25519::VerifyKey.new(Base64.strict_decode64(pub).byteslice(12, 32))
    assert key.verify(Base64.strict_decode64(sig), "hub1:#{hub_key}:#{nonce}:#{expiry}")
  end

  def service_bytes
    HubServiceRB::Keychain.decode_key_file(VECTORS['keys']['service']['keyFile'])
  end

  def test_token_matches_vector
    auth = VECTORS['auth']
    assert_equal auth['v1']['header'], HubServiceRB::Keychain.token(service_bytes, auth['expiry'], HUB_KEY, auth['nonce'])
  end

  def test_proof_matches_vector
    info = VECTORS['hubInfo']
    assert_equal info['signedData'], HubServiceRB.hub_info_signed_data(HUB_KEY, info['nonce'])
    answer = { 'key' => HUB_KEY, 'proof' => info['proof'], 'challenge' => 'c' }
    assert HubServiceRB.verify_hub_proof(answer, info['nonce'])
    refute HubServiceRB.verify_hub_proof(answer, 'another-nonce-another-nonce')
    refute HubServiceRB.verify_hub_proof(answer.merge('key' => VECTORS['keys']['service']['publicKey']), info['nonce'])
    refute HubServiceRB.verify_hub_proof({ 'key' => HUB_KEY, 'challenge' => 'c' }, info['nonce'])
    refute HubServiceRB.verify_hub_proof({ 'key' => HUB_KEY, 'proof' => info['proof'] }, info['nonce'])
    refute HubServiceRB.verify_hub_proof('no answer', info['nonce'])
  end

  def test_transport_matches_vector
    VECTORS['transport'].each do |vector|
      assert_equal vector['transport'], HubServiceRB.hub_transport_of(vector['url']), vector['url']
    end
    assert_equal 'loopback', HubServiceRB.hub_transport_of(1997)
    assert_equal 'loopback', HubServiceRB.hub_transport_of('1997')
  end

  def test_client_nonce_is_32_bytes_of_base64url
    nonce = HubServiceRB.make_client_nonce
    assert_equal 32, Base64.urlsafe_decode64(nonce).bytesize
    refute_includes nonce, '='
    refute_equal nonce, HubServiceRB.make_client_nonce
  end

  def test_token_lasts_thirty_seconds_over_the_challenge
    token = HubServiceRB::Keychain.sign(HUB_KEY, 'challenge')
    verify(token)
    assert_equal 'challenge', token.split('.')[4]
    assert_includes 25..31, token.split('.')[3].to_i - Time.now.to_i
  end

  def test_pins_round_trip
    pins = HubServiceRB::HubPins.new(File.join(@dir, 'hubs.json'))
    assert_nil pins.get('ws://localhost:1997')
    pins.set('ws://localhost:1997', HUB_KEY)
    assert_equal({ 'ws://localhost:1997' => HUB_KEY }, JSON.parse(File.read(File.join(@dir, 'hubs.json'))))
    pins.forget('ws://localhost:1997')
    assert_nil pins.get('ws://localhost:1997')
  end

  def test_pin_address_normalization
    assert_equal 'ws://localhost:1997', HubServiceRB::Keychain.pin_address(1997)
    assert_equal 'ws://localhost:1997', HubServiceRB::Keychain.pin_address('1997')
    assert_equal 'ws://hub.example.com:2000', HubServiceRB::Keychain.pin_address('WS://Hub.Example.COM:2000/')
    assert_equal 'wss://hub.example.com/Path', HubServiceRB::Keychain.pin_address('wss://hub.example.com/Path/')
  end

  def test_sends_a_token_only_after_proof_and_pins_the_key
    @service = HubServiceRB::Service.new(address: FakeHub.port).start
    # A call made right away waits for the authenticated connection.
    assert_equal 'hi', Timeout.timeout(5) { @service.send('test/echo', 'hi') }
    headers = FakeHub.headers
    refute headers.first.key?('auth')
    refute headers.first.key?('device')
    assert_equal '1', headers.last['v']
    assert headers.last.key?('device')
    verify(headers.last['auth'])
    assert_equal 'challenge-1', headers.last['auth'].split('.')[4]
    assert_equal HUB_KEY, HubServiceRB::HubPins.new(File.join(@dir, 'hubs.json')).get(@service.target)
    @service.forget_hub_key
    assert_nil @service.hub_key
  end

  def test_each_connect_has_its_own_challenge
    nonces = []
    prove = FakeHub.proving
    FakeHub.answer = lambda do |nonce, challenge|
      nonces << nonce
      prove.call(nonce, challenge)
    end
    @service = HubServiceRB::Service.new(address: FakeHub.port).start
    FakeHub.wait_updates(1)
    @service.instance_variable_get(:@sender).ws.instance_variable_get(:@connection).close # the reconnect asks again
    FakeHub.wait_updates(2)
    assert_equal 2, nonces.length
    refute_equal nonces[0], nonces[1]
    tokens = FakeHub.credentials.map { |h| h['auth'] }
    assert_equal %w[challenge-1 challenge-2], tokens.map { |t| t.split('.')[4] }
    tokens.each { |token| verify(token) }
  end

  def test_hub_without_a_proof_gets_nothing_and_is_not_pinned
    prove_with_service_key = FakeHub.proving('service')
    [
      ->(_nonce, challenge) { { key: HUB_KEY, protocol: 2, challenge: challenge } },
      # Claims the real hub's key, signs with its own.
      ->(nonce, challenge) { prove_with_service_key.call(nonce, challenge).merge(key: HUB_KEY) }
    ].each do |answer|
      FakeHub.reset
      FakeHub.answer = answer
      err = capture_stderr do
        @service = HubServiceRB::Service.new(address: FakeHub.port).start
        sleep 1.5
      end
      assert_operator FakeHub.headers.length, :>=, 2, 'it keeps asking'
      assert_empty FakeHub.credentials
      assert_equal 0, FakeHub.updates
      assert_nil @service.hub_key
      refute File.exist?(File.join(@dir, 'hubs.json'))
      assert_includes @service.last_error, "didn't prove"
      assert_equal 1, err.scan("didn't prove").length
      @service.stop
    end
  end

  def test_hub_with_another_key_than_the_pin_gets_nothing
    # Proves its own key, but this address is pinned to the real hub's.
    FakeHub.answer = FakeHub.proving('service')
    @service = HubServiceRB::Service.new(address: FakeHub.port)
    @service.pins.set(@service.target, HUB_KEY)
    capture_stderr do
      @service.start
      sleep 1.2
    end
    assert_empty FakeHub.credentials
    assert_equal 0, FakeHub.updates
    assert_equal HUB_KEY, @service.pins.get(@service.target)
    assert_includes @service.last_error, 'not the pinned'
  end

  def test_supplied_hub_key_is_a_pin
    FakeHub.answer = FakeHub.proving('service')
    capture_stderr do
      @service = HubServiceRB::Service.new(address: FakeHub.port, hub_key: HUB_KEY).start
      sleep 0.5
    end
    assert_empty FakeHub.credentials
    assert_equal HUB_KEY, @service.hub_key
  end

  def test_stop_ends_the_wait_for_a_proof
    FakeHub.answer = ->(_nonce, challenge) { { key: HUB_KEY, challenge: challenge } }
    service = nil
    capture_stderr do
      service = HubServiceRB::Service.new(address: FakeHub.port, device: false).start
      sleep 0.3
      service.stop
      asked = FakeHub.headers.length
      sleep 1.5
      assert_operator FakeHub.headers.length, :<=, asked + 1
    end
  end

  def test_custom_sign_gets_the_proven_key_and_challenge_after_the_proof
    calls = []
    sign = lambda do |hub_key, challenge|
      calls << [hub_key, challenge]
      HubServiceRB::Keychain.sign(hub_key, challenge)
    end
    FakeHub.answer = ->(_nonce, challenge) { { key: HUB_KEY, challenge: challenge } }
    capture_stderr do
      @service = HubServiceRB::Service.new(address: FakeHub.port, device: false, sign: sign).start
      sleep 0.4
    end
    assert_empty calls
    @service.stop

    FakeHub.reset
    @service = HubServiceRB::Service.new(address: FakeHub.port, device: false, sign: sign).start
    FakeHub.wait_updates(1)
    assert_equal [[HUB_KEY, 'challenge-1']], calls
  end

  def test_public_plaintext_is_not_dialed
    ENV.delete('HUB_ALLOW_PLAINTEXT')
    service = nil
    err = capture_stderr { service = HubServiceRB::Service.new(address: 'ws://hub.example.com:1997').start }
    assert_includes err, 'unencrypted'
    assert_nil service.instance_variable_get(:@sender)
    assert_includes assert_raises(HubServiceRB::Error) { service.send('x') }.message, 'unencrypted'
    assert_includes service.last_error, 'unencrypted'
  end

  def test_schemes_this_client_cant_encrypt_are_not_dialed
    ['https://hub.example.com', 'quic://hub.example.com:1997'].each do |address|
      service = nil
      capture_stderr { service = HubServiceRB::Service.new(address: address, allow_plaintext: true).start }
      assert_nil service.instance_variable_get(:@sender)
      assert_includes service.last_error, 'unencrypted'
    end
  end

  def test_allow_plaintext_opts_out
    service = HubServiceRB::Service.new(address: 'ws://hub.invalid-name:1', allow_plaintext: true)
    capture_stderr { service.start }
    refute_nil service.instance_variable_get(:@sender)
    service.stop
    begin
      ENV['HUB_ALLOW_PLAINTEXT'] = '1'
      service = HubServiceRB::Service.new(address: 'ws://hub:1')
      capture_stderr { service.start }
      refute_nil service.instance_variable_get(:@sender)
      service.stop
    ensure
      ENV.delete('HUB_ALLOW_PLAINTEXT')
    end
  end

  private

  def capture_stderr
    capture_io { yield }.last
  end
end
