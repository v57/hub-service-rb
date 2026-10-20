# frozen_string_literal: true

require 'json'
require 'minitest/autorun'
require 'timeout'
require 'tmpdir'

require_relative 'fake_hub'

# Caller identity from context.hub.caller (protocol.md §4).
class TestCaller < Minitest::Test
  VECTORS = JSON.parse(File.read(File.expand_path('../../../Docs/Devices/vectors.json', __dir__)))
  CONTEXT = VECTORS['caller']['context']
  Caller = HubServiceRB::Caller

  def test_parse_caller
    caller = Caller.parse(CONTEXT['hub']['caller'])
    assert_equal 'MCowBQYDK2VwAyEAgTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Q=', caller.key
    assert_equal HubServiceRB::CallerDevice.new('8cef065b7af83669150b7d32704d3d3e', 'Mac Studio'), caller.device
    assert_equal ['owners'], caller.groups
    assert_equal true, caller.owner
    assert_nil caller.via
  end

  def test_parse_anonymous_and_merged_callers
    assert_equal Caller.new(nil, nil, [], false, nil, nil), Caller.parse('groups' => [])
    merged = Caller.parse('key' => 'A', 'via' => 'H', 'claimed' => { 'key' => 'B', 'owner' => true })
    assert_equal 'H', merged.via
    assert_equal Caller.new('B', nil, [], true, nil, nil), merged.claimed
    assert_nil Caller.parse(nil)
  end

  def test_handlers_get_the_caller
    dir = Dir.mktmpdir('hubcaller-rb')
    HubServiceRB::Keychain.key_path = File.join(dir, 'auth')
    saved = ENV['HUB_DEVICE_KEY']
    ENV['HUB_DEVICE_KEY'] = File.join(dir, 'device.key')
    FakeHub.start
    FakeHub.reset
    results = Queue.new
    FakeHub.on_update = proc do |sender|
      begin
        results << {
          post: sender.send('whoami', 'hi', CONTEXT),
          plain: sender.send('echo', 'hi', CONTEXT),
          lambda: sender.send('upper', 'hi', CONTEXT),
          stream: sender.values('whoami/values', nil, CONTEXT).to_a,
          anonymous: sender.send('whoami', 'hi', 'service' => 'x'),
          spoofed: sender.send('whoami', 'hi', 'hub' => CONTEXT['hub'].merge('hubKey' => 'OTHER'))
        }
      rescue StandardError => e
        results << { error: e.message }
      end
    end
    service = HubServiceRB::Service.new(address: FakeHub.port, hub_key: CONTEXT['hub']['hubKey'])
    service.post('whoami') do |body, request|
      caller = request.caller || Caller.new
      [body, caller.key, caller.owner == true, request.context.keys.sort]
    end
    service.post('echo') { |body| body }
    service.post('upper', &->(body) { body.upcase })
    service.stream('whoami/values') { |_body, request| [request.caller.device.name] }
    service.start
    result = Timeout.timeout(5) { results.pop }
    refute result.key?(:error), result[:error]
    assert_equal ['hi', CONTEXT['hub']['caller']['key'], true, []], result[:post]
    assert_equal 'hi', result[:plain]
    assert_equal 'HI', result[:lambda]
    assert_equal ['Mac Studio'], result[:stream]
    assert_equal ['hi', nil, false, ['service']], result[:anonymous]
    # A caller is trusted only from the pinned hub.
    assert_equal ['hi', nil, false, []], result[:spoofed]
  ensure
    FakeHub.on_update = nil
    service&.instance_variable_get(:@sender)&.stop
    ENV['HUB_DEVICE_KEY'] = saved
    HubServiceRB::Keychain.key_path = nil
    FileUtils.remove_entry(dir) if dir
  end
end
