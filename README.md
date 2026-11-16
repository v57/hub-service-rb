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

Not published as a gem. `lib/hub_service_rb.rb` loads [channel-rb](https://github.com/v57/channel-rb) (no
gemspec either) from `../../Channel/channel-rb/lib`, so clone both into the Hub layout:

```bash
mkdir -p Hub/Channel Hub/HubService
git clone https://github.com/v57/channel-rb Hub/Channel/channel-rb
git clone https://github.com/v57/hub-service-rb Hub/HubService/hub-service-rb
cd Hub/HubService/hub-service-rb
bundle config set --local path vendor/bundle
bundle install
```

The Gemfile lists channel-rb's gems (oj, iodine) as well as this port's. When `channel_rb` is already on the load
path (a path ending in `/channel-rb/lib`), the sibling folder isn't needed.

## Usage

Start a hub first (hub-server, listens on 1997), then:

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
  `1997` or `$HUB`), `:name`, `:icon` (string or `{symbol:, text:}`),
  `:allow_plaintext`, `:sign` (custom token factory given the proven hub key
  and the challenge)
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
- `#stop -> self` — disconnects, ending a wait for the hub's proof

`settings` = `{ permissions: { group:, name:, allows: }, limit: }` — wire-parity
fields hub-lite ignores; `group` auto-fills from the first path segment when
missing (TS parity).

Element helpers (`lib/hub_service_rb/app.rb`): `text`, `progress`, `text_field`,
`button`, `slider`, `list`, `picker`, `cell`, `files`, `file_operation`,
`hstack`, `vstack`, `zstack`, `spacer`, `action`.

## Auth and devices

- **Service key:** the `auth` file in the cwd (or `$HUBKEY`, TS layout), sent
  as a signed `auth` token on every connect.
- **Hub key:** before every connect the service asks `hub/info` with a fresh
  nonce on a short anonymous connection. Only an answer with a valid proof of
  the key it claims gets a token, signing `hub1:<hub key>:<challenge>:<expiry>`
  with `v: 1`. The first proven key is pinned in `hubs.json` beside the `auth`
  file. A hub that doesn't prove its key, or answers with another than the
  pinned one, gets nothing and is reported (`#last_error`) while the service
  keeps trying, so calls made right after `#start` wait instead of being lost.
  `:hub_key` supplies it up front and `#forget_hub_key` clears the pin.
- **Transport:** plain `ws://` beyond loopback, the overlay and the LAN isn't
  dialed unless `:allow_plaintext` or `HUB_ALLOW_PLAINTEXT=1` says so;
  `HubServiceRB.hub_transport_of(address)` classifies an address.
- **Device:** a certificate signed by `~/.hub/device.key` (`HUB_DEVICE_KEY`
  overrides it) goes in the `device` header and is renewed with less than a
  day left. `:instance` sets the instance name and `device: false` turns
  device mode off; `HubServiceRB::Device.new(name:, platform:, parent:, key:)`
  overrides the defaults.

## Hub Network shares

A share makes a local TCP/UDP port reachable through Hub Network (TS
`publishShare` parity). The local hub-net agent attests each share over its
Unix socket (`/var/run/hub-net/agent.sock`, `service.network.agent_socket`),
then the declared set goes to the hub in one `network/shares/replace`, and it
is republished after every reconnect.

```ruby
service.share('s3', 'tcp', '127.0.0.1', 9001, mode: 'hub')  # before start
service.publish_share('ssh', 'tcp', '127.0.0.1', 22)         # after start
service.update_share('ssh', port: 2222)
service.remove_share('ssh')
service.share_publication('s3') # {'resourceId', 'authority', 'overlayAddress', 'port', ...}
```

The default policy is `{ mode: 'private' }`; others are `hub`, `group`
(`group:`), `keys` (`keys:`) and `disabled`.

## Test

```bash
./scripts/test            # unit tests
bundle exec ruby -Ilib example/echo.rb   # example service (needs a hub on 1997)
# cross-language check (TS):
bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
```
