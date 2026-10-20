<h1>
  <img alt="Hub Service logo" src="./icon.png" width="70" valign="middle">
  &nbsp;hub-service-rb
</h1>

Ruby port of [hub-service](https://github.com/v57/hub-service) — connect to a
[hub](https://github.com/v57/hub-lite) (default `ws://127.0.0.1:1997`), host
your own post/stream API endpoints, register apps, and call API through the hub.

The wire contract matches the TS reference (`hub/profile/update`,
`hub/service/update`, AppInterface + element DSL). Auth and devices follow
[`Docs/Devices/protocol.md`](../../Docs/Devices/protocol.md).

## Install

```bash
# sibling checkout of channel-rb (monorepo layout):
git clone https://github.com/v57/channel-rb
git clone https://github.com/v57/hub-service-rb
cd hub-service-rb
bundle install --path vendor/bundle
```

`hub-service-rb` depends on the [channel-rb](https://github.com/v57/channel-rb)
client (repo has no gemspec, so it is wired via the sibling load path).

## Usage

Start a hub first (hub-lite, listens on 1997), then:

```ruby
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
    ]
  )
)

service.start
sleep
```

Call it through the hub (any language):

```ruby
response = service.send('echo/upper', 'hello') # "HELLO"
service.values('echo/values', 'x').each { |v| p v }
```

## API

- `Service.new(options = {})` — `:address` (port or `ws://` URL; default
  `1997` or `$HUB`), `:name`, `:icon` (string or `{symbol:, text:}`)
- `#post(path, settings = nil) { |body| ... }` — registers an endpoint; the
  block's return value is the response
- `#stream(path, settings = nil) { |body| ... }` — registers a streaming
  endpoint; the block must return an enumerable of values
- Either block may name a second argument, a `HubServiceRB::Request`:
  `request.caller` (`Caller`: `key`, `device` (`id`, `name`), `groups`,
  `owner`, `via`, `claimed`), `request.context` (without `hub`),
  `request.path`. The caller is nil unless `context.hub.hubKey` is the
  pinned hub key: a hub that predates caller identity may pass a client's
  `context.hub` through.
- `#app(App) -> self` — appends the header to the apps list and streams the
  AppInterface at the app path
- `#send(path, body = nil, context = nil)` — client call through the hub
  (raises `HubServiceRB::Error` if not started)
- `#values(path, body = nil, context = nil)` — stream call through the hub
  (returns an enumerable)
- `#start -> self` — connects; on every (re)connect sends
  `hub/profile/update` (if set) then `hub/service/update`

`settings` = `{ permissions: { group:, name:, allows: }, limit: }` — wire-parity
fields hub-lite ignores; `group` auto-fills from the first path segment when
missing (TS parity).

Element helpers (`lib/hub_service_rb/app.rb`): `text`, `progress`, `text_field`,
`button`, `slider`, `list`, `picker`, `cell`, `files`, `file_operation`,
`hstack`, `vstack`, `zstack`, `spacer`, `action`.

## Auth and devices

- **Service key:** the `auth` file in the cwd (or `$HUBKEY`, TS layout), sent
  as a signed `auth` token on every connect.
- **Hub key:** the first connect uses `v: 0` and calls `hub/info`; the hub key
  is pinned in `hubs.json` beside the `auth` file and later connects sign
  `hub1:<hub key>:<expiry>` with `v: 1`. hub-lite stays on v0. `:hub_key`
  supplies it up front and `#forget_hub_key` clears the pin.
- **Device:** a certificate signed by `~/.hub/device.key` (`HUB_DEVICE_KEY`
  overrides it) goes in the `device` header and is renewed with less than a
  day left. `:instance` sets the instance name and `device: false` turns
  device mode off; `HubServiceRB::Device.new(name:, platform:, parent:, key:)`
  overrides the defaults.

## Test

```bash
./scripts/test            # unit tests
bundle exec ruby -Ilib example/echo.rb   # example service (needs a hub on 1997)
# cross-language check (TS):
bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
```
