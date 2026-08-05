# frozen_string_literal: true

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'hub_service_rb'

service = HubServiceRB::Service.new(
  name: 'Echo',
  icon: { symbol: 'speaker.wave.2', text: 'E' }
)

service.post('echo') { |body| body }
service.post('echo/upper') { |body| body.to_s.upcase }

service.app(
  HubServiceRB::App.new(
    header: { type: 'app', name: 'Echo', path: 'echo/ui' },
    body: [
      'Hello from Ruby',
      HubServiceRB.text_field('echo', 'Text to echo', HubServiceRB.action('echo/upper', 'value', 'value')),
      HubServiceRB.cell('$Echo', 'value'),
      HubServiceRB.button('Upper', HubServiceRB.action('echo/upper', 'value', 'value'))
    ],
    data: { hello: 'world' }
  )
)

service.start
puts 'echo service started (hub-lite :1997)'
loop { sleep 1 }
