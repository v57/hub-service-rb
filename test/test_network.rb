# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'minitest/autorun'
require 'socket'
require 'time'
require 'tmpdir'

require_relative 'fake_hub'

# The hub-net agent's /challenge and /attest over a Unix socket.
class FakeAgent
  def initialize(path, expired: false)
    @path = path
    @expired = expired
    @nonces = {}
    @server = UNIXServer.new(path)
    @thread = Thread.new { loop { handle(@server.accept) } }
  end

  def stop
    @thread.kill
    @server.close
  end

  private

  def handle(client)
    head = +''
    head << client.readpartial(4096) until head.include?("\r\n\r\n")
    head, body = head.split("\r\n\r\n", 2)
    length = head[/content-length: *(\d+)/i, 1].to_i
    body << client.read(length - body.bytesize) while body.bytesize < length
    status, reply = route(head.split(' ')[1], JSON.parse(body))
    data = reply.is_a?(String) ? reply : JSON.generate(reply)
    client.write("HTTP/1.1 #{status} OK\r\nContent-Length: #{data.bytesize}\r\n\r\n#{data}")
  ensure
    client.close
  end

  def route(path, body)
    name = body['shareName']
    case path
    when '/challenge'
      @nonces[name] = "nonce-#{name}"
      [200, { 'nonce' => @nonces[name] }]
    when '/attest'
      key = Ed25519::VerifyKey.new(Base64.strict_decode64(body['serviceKey']).byteslice(12, 32))
      begin
        key.verify(Base64.strict_decode64(body['signature']), @nonces[name])
      rescue StandardError
        return [403, 'bad signature']
      end
      issued = Time.now.utc + (@expired ? -600 : 0)
      [200, { 'version' => 1, 'attestationId' => "att-#{name}", 'serviceKey' => body['serviceKey'],
              'key' => 'agent-key', 'shareName' => name, 'protocol' => body['protocol'], 'target' => body['target'],
              'issuedAt' => issued.iso8601, 'expiresAt' => (issued + 300).iso8601, 'signature' => 'c2lnbmF0dXJl' }]
    else [404, 'not found']
    end
  end
end

# Hub Network share publication against a fake agent and hub (TS network.ts parity).
class TestNetwork < Minitest::Test
  Network = HubServiceRB::Network

  def setup
    @dir = Dir.mktmpdir('hubnet-rb')
    @socket_dir = Dir.mktmpdir('hn', '/tmp') # Unix socket paths are short
    @socket = File.join(@socket_dir, 'agent.sock')
    HubServiceRB::Keychain.key_path = File.join(@dir, 'auth')
    FakeHub.start
    FakeHub.reset
  end

  def teardown
    @service&.instance_variable_get(:@sender)&.stop
    @agent&.stop
    HubServiceRB::Keychain.key_path = nil
    FileUtils.remove_entry(@dir)
    FileUtils.remove_entry(@socket_dir)
  end

  def share(name = 's3', port = 9001)
    { 'name' => name, 'protocol' => 'tcp', 'target' => { 'host' => '127.0.0.1', 'port' => port } }
  end

  def test_share_validation
    Network.validate_share(share)
    [share.merge('name' => ''), share.merge('protocol' => 'sctp'),
     share.merge('target' => { 'host' => 'h', 'port' => 70_000 }),
     share.merge('policy' => { 'mode' => 'keys', 'keys' => [] })].each do |bad|
      assert_raises(ArgumentError) { Network.validate_share(bad) }
    end
  end

  def test_declared_shares_publish_on_connect_and_update
    @agent = FakeAgent.new(@socket)
    @service = HubServiceRB::Service.new(address: FakeHub.port, hub_key: FakeHub::HUB_KEY, device: false)
    @service.network.agent_socket = @socket
    @service.share('s3', 'tcp', '127.0.0.1', 9001, mode: 'hub').start
    100.times { break if @service.share_publication('s3'); sleep 0.02 }
    wire = FakeHub.replaced.first['shares'].first
    assert_equal ['s3', 1, { 'mode' => 'hub' }], [wire['name'], wire['version'], wire['policy']]
    assert_equal HubServiceRB::Keychain.public_key, wire['attestation']['serviceKey']
    assert_equal 'hnr1_s3', @service.share_publication('s3')['resourceId']

    @service.publish_share('ssh', 'tcp', '127.0.0.1', 22)
    assert_equal %w[s3 ssh], FakeHub.replaced.last['shares'].map { |s| s['name'] }
    assert_equal({ 'mode' => 'private' }, FakeHub.replaced.last['shares'][1]['policy'])

    @service.update_share('ssh', port: 2222)
    assert_equal({ 'host' => '127.0.0.1', 'port' => 2222 }, FakeHub.replaced.last['shares'][1]['target'])
    assert_equal 2222, @service.share_publication('ssh')['port']

    @service.remove_share('s3')
    assert_equal %w[ssh], FakeHub.replaced.last['shares'].map { |s| s['name'] }
    assert_equal %w[hnr1_ssh], @service.share_publications.map { |p| p['resourceId'] }
  end

  def test_expired_attestation_is_refused_and_rolled_back
    @agent = FakeAgent.new(@socket, expired: true)
    publisher = Network::Publisher.new(agent_socket: @socket)
    sign = ->(data) { HubServiceRB::Keychain.sign_data(data) }
    error = assert_raises(Network::LocalAgentError) do
      publisher.publish_share(share, HubServiceRB::Keychain.public_key, sign, Object.new)
    end
    assert_equal 'attestation-expired', error.code
    refute publisher.shares?
  end

  def test_agent_unavailable_and_rejected
    publisher = Network::Publisher.new(agent_socket: @socket)
    sign = ->(data) { HubServiceRB::Keychain.sign_data(data) }
    error = assert_raises(Network::LocalAgentError) do
      publisher.request_attestation(share, HubServiceRB::Keychain.public_key, sign)
    end
    assert_equal 'agent-unavailable', error.code

    @agent = FakeAgent.new(@socket)
    error = assert_raises(Network::LocalAgentError) do
      publisher.request_attestation(share, HubServiceRB::Keychain.public_key, ->(_) { 'AAAA' })
    end
    assert_equal ['agent-rejected', 403], [error.code, error.status]
  end
end
