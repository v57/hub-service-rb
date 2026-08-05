# frozen_string_literal: true

require 'minitest/autorun'
require 'hub_service_rb'

class TestService < Minitest::Test
  def test_services_list_includes_registered_paths
    s = HubServiceRB::Service.new
    s.post('echo') { |body| body }
    s.stream('echo/values') { |body| [body] }
    s.app(HubServiceRB::App.new(header: { type: 'app', name: 'Echo', path: 'echo/ui' }, body: ['hi']))

    u = s.update
    assert_equal %w[echo echo/ui echo/values], u[:services].map { |svc| svc[:path] }
    assert_equal 1, u[:apps].length
    assert_equal 'app', u[:apps][0][:type]
    assert_equal 'Echo', u[:apps][0][:name]
    assert_equal 'echo/ui', u[:apps][0][:path]
  end

  def test_settings_apply_to_update_payload
    s = HubServiceRB::Service.new
    s.post('echo', permissions: { name: 'Echo', allows: true }, limit: 5) { |body| body }

    u = s.update
    assert_equal 1, u[:services].length
    svc = u[:services][0]
    assert_equal 5, svc[:limit]
    assert_equal({ group: 'echo', name: 'Echo', allows: true }, svc[:permissions])
  end

  def test_group_auto_fill_uses_first_path_segment
    s = HubServiceRB::Service.new
    s.post('foo/bar', permissions: { name: 'Bar' }) { |body| body }
    perms = s.update[:services][0][:permissions]
    assert_equal 'foo', perms[:group]
  end

  def test_profile_only_when_set
    assert_nil HubServiceRB::Service.new.profile

    s = HubServiceRB::Service.new(name: 'Echo')
    assert_equal({ name: 'Echo' }, s.profile)

    s = HubServiceRB::Service.new(icon: 'speaker.wave.2')
    assert_equal({ icon: 'speaker.wave.2' }, s.profile)

    s = HubServiceRB::Service.new(name: 'Echo', icon: { symbol: 'speaker.wave.2', text: 'E' })
    assert_equal({ name: 'Echo', icon: { symbol: 'speaker.wave.2', text: 'E' } }, s.profile)
  end

  def test_profile_json_matches_wire_contract
    s = HubServiceRB::Service.new(name: 'Echo', icon: { symbol: 'speaker.wave.2', text: 'E' })
    raw = ChannelRB::JSONCodec.dump(s.profile)
    assert_equal '{"name":"Echo","icon":{"symbol":"speaker.wave.2","text":"E"}}', raw
  end

  def test_update_json_matches_wire_contract
    s = HubServiceRB::Service.new
    s.post('echo', permissions: { name: 'Echo', allows: true }, limit: 5) { |body| body }

    raw = ChannelRB::JSONCodec.dump(s.update)
    want = '{"services":[{"path":"echo","permissions":{"group":"echo","name":"Echo","allows":true},"limit":5}],"apps":[]}'
    assert_equal want, raw
  end

  def test_send_before_start_raises
    s = HubServiceRB::Service.new
    error = assert_raises(HubServiceRB::Error) { s.send('echo', 'x') }
    assert_equal 'Service not started', error.message
    assert_raises(HubServiceRB::Error) { s.values('echo', 'x') }
  end

  def test_element_helpers_match_wire_shapes
    assert_equal({ type: 'text', value: 'hi' }, HubServiceRB.text('hi'))
    assert_equal({ type: 'textField', value: 'echo', placeholder: 'Text', action: { path: 'echo/upper' } },
                 HubServiceRB.text_field('echo', 'Text', HubServiceRB.action('echo/upper')))
    assert_equal({ type: 'button', title: 'Upper', action: { path: 'echo/upper', body: 'value', output: 'value' } },
                 HubServiceRB.button('Upper', HubServiceRB.action('echo/upper', 'value', 'value')))
    assert_equal({ type: 'cell', title: '$Echo', subtitle: 'value' }, HubServiceRB.cell('$Echo', 'value'))
    assert_equal({ type: 'progress', value: 'p', min: 0, max: 10 }, HubServiceRB.progress('p', 0, 10))
    assert_equal({ type: 'spacer' }, HubServiceRB.spacer)
    assert_equal({ type: 'hstack', content: ['a'], spacing: 4 }, HubServiceRB.hstack(['a'], 4))
  end
end
