# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'minitest/autorun'
require 'tmpdir'

require_relative 'fake_hub'

# v1 hub-bound auth: hub/info pinning against a fake hub (protocol.md §2).
class TestAuth < Minitest::Test
  HUB_KEY = FakeHub::HUB_KEY

  def setup
    @dir = Dir.mktmpdir('hubauth-rb')
    HubServiceRB::Keychain.key_path = File.join(@dir, 'auth')
    FakeHub.start
    FakeHub.reset
  end

  def teardown
    @service&.instance_variable_get(:@sender)&.stop
    HubServiceRB::Keychain.key_path = nil
    FileUtils.remove_entry(@dir)
  end

  def verify(token, signed)
    _, pub, sig, = token.split('.')
    key = Ed25519::VerifyKey.new(Base64.strict_decode64(pub).byteslice(12, 32))
    assert key.verify(Base64.strict_decode64(sig), signed)
  end

  def test_v0_and_v1_tokens
    token = HubServiceRB::Keychain.sign
    verify(token, token.split('.')[3])
    token = HubServiceRB::Keychain.sign(hub_key: HUB_KEY)
    verify(token, "hub1:#{HUB_KEY}:#{token.split('.')[3]}")
  end

  def test_default_expiry_is_sixty_seconds
    expiry = HubServiceRB::Keychain.sign.split('.')[3].to_i
    assert_includes 55..61, expiry - Time.now.to_i
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

  def test_supplied_hub_key_connects_v1
    headers = HubServiceRB::Service.new(address: 1, hub_key: HUB_KEY).auth_headers
    assert_equal '1', headers['v']
    verify(headers['auth'], "hub1:#{HUB_KEY}:#{headers['auth'].split('.')[3]}")
  end

  def test_sign_without_arguments_stays_v0
    service = HubServiceRB::Service.new(address: 1, hub_key: HUB_KEY, sign: -> { HubServiceRB::Keychain.sign })
    assert_equal '0', service.auth_headers['v']
  end

  def test_learns_and_pins_hub_key_then_reconnects_v1
    @service = HubServiceRB::Service.new(address: FakeHub.port).start
    FakeHub.wait_connects(2)
    headers = FakeHub.headers
    assert_equal %w[0 1], headers.first(2).map { |h| h['v'] }
    verify(headers[1]['auth'], "hub1:#{HUB_KEY}:#{headers[1]['auth'].split('.')[3]}")
    assert_equal HUB_KEY, HubServiceRB::HubPins.new(File.join(@dir, 'hubs.json')).get(@service.target)
    @service.forget_hub_key
    assert_nil @service.hub_key
  end

  def test_hub_lite_keeps_v0
    FakeHub.lite = true
    @service = HubServiceRB::Service.new(address: FakeHub.port).start
    FakeHub.wait_connects(1)
    sleep 0.3
    assert_equal %w[0], FakeHub.headers.map { |h| h['v'] }
    refute File.exist?(File.join(@dir, 'hubs.json'))
  end
end
