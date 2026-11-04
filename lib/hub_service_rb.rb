# frozen_string_literal: true

# hub-service-rb: Ruby port of hub-service (TS reference).
# Connects with hub-server auth (keychain + signed tokens). Auth follows
# Docs/Devices/protocol.md section 2: every (re)connect asks the hub to prove
# its key and sends a fresh token for that answer alone (see hub_proof.rb).

# channel-rb is a sibling checkout (no gemspec), wired via the monorepo layout.
# If channel_rb is already available as a gem, the load path stays untouched.
unless $LOAD_PATH.any? { |p| p.end_with?('/channel-rb/lib') }
  $LOAD_PATH.unshift(File.expand_path('../../../Channel/channel-rb/lib', __dir__))
end

require 'thread'
require 'channel_rb'
require 'hub_service_rb/app'
require 'hub_service_rb/keychain'
require 'hub_service_rb/hub_proof'
require 'hub_service_rb/device'
require 'hub_service_rb/request'
require 'hub_service_rb/network'

module HubServiceRB
  # Raised when calling the hub before the service is started.
  class Error < StandardError; end

  # Retry delays (seconds) for a hub that doesn't prove its key, or can't be reached.
  HANDSHAKE_RETRY = 1
  HANDSHAKE_MAX_RETRY = 30

  # Service registers API endpoints on a hub and serves calls forwarded by it.
  class Service
    # last_error: why the service isn't connected, if it knows: a refused
    # address, or a hub that didn't prove its key or answers with another than
    # the pinned one.
    attr_reader :apps, :profile, :device, :network, :last_error

    # options: :address (port or ws:// URL; default 1997 or $HUB), :name, :icon
    # (string or {symbol:, text:}), :sign (callable returning a fresh hub-server
    # auth token; default: the keychain +auth+ file in the cwd, TS parity. It
    # gets the key the hub proved and the challenge of this connect, and runs
    # only after the proof), :hub_key (the hub's key when known up front;
    # otherwise the first key a hub proves is pinned), :allow_plaintext (dial
    # plain ws:// beyond loopback, the overlay and the LAN, which would carry
    # the key unencrypted: for private networks the SDK can't recognize, such
    # as a container's ws://hub:1997; also HUB_ALLOW_PLAINTEXT=1), :instance (this service's name on its
    # device, unique per device; default: HUB_INSTANCE, else :name, else the
    # cwd name, else 'service'), :device (true, the
    # default, certifies the service with this device's key when it can be
    # read or created; false sends no device header; a Device uses that one),
    # :sign_challenge (signs Hub Network agent challenges with the service
    # key; default: the keychain +auth+ file).
    def initialize(options = {})
      hub = ENV['HUB']
      hub = hub&.match?(/\A\d+\z/) ? hub.to_i : hub
      @address = options[:address] || hub || 1997
      @sign = options[:sign] || ->(hub_key, nonce) { HubServiceRB::Keychain.sign(hub_key, nonce) }
      @allow_plaintext = options[:allow_plaintext] || ENV['HUB_ALLOW_PLAINTEXT'] == '1'
      @hub_key = options[:hub_key]
      @instance = options[:instance]
      device = options.fetch(:device, true)
      @device = device.is_a?(Device) ? device : (device ? Device.new : nil)
      @sign_challenge = options[:sign_challenge] || ->(data) { HubServiceRB::Keychain.sign_data(data) }
      # Hub Network shares; the agent socket is network.agent_socket.
      @network = Network::Publisher.new
      profile = {}
      profile[:name] = options[:name] if options[:name]
      profile[:icon] = options[:icon] unless options[:icon].nil?
      @profile = profile.empty? ? nil : profile
      @channel = ChannelRB::Channel.new
      @apps = []
      @paths = {}
      @settings = {}
      @sender = nil
      @mutex = Mutex.new
    end

    # Register a request/response API endpoint. The handler receives the
    # request body and its return value is the response. A block (or a
    # lambda taking two arguments) also gets the Request: +request.caller+
    # is who is calling.
    def post(path, settings = nil, &handler)
      add_path(path, settings)
      @channel.post(path) { |payload| call_handler(handler, payload) }
      self
    end

    # Register a streaming API endpoint. The handler receives the request body
    # (and the Request, as in post) and must return an enumerable of values
    # (Enumerator, Array, ...).
    def stream(path, settings = nil, &handler)
      add_path(path, settings)
      @channel.stream(path) { |payload| call_handler(handler, payload) }
      self
    end

    # Register an app: its header goes to the hub apps list and its path
    # streams the AppInterface (header/body/top/bottom/data) as first value.
    def app(app)
      @mutex.synchronize { @apps << app.header }
      add_path(app.header[:path], nil)
      @channel.stream(app.header[:path]) do |_payload|
        [{ header: app.header, body: app.body, top: app.top, bottom: app.bottom, data: app.data }]
      end
      self
    end

    # Call an API through the hub. Raises Error if not started.
    def send(path, body = nil, context = nil)
      sender.send(path, body, context)
    end

    # Open a stream call through the hub. Raises Error if not started.
    # Returns an enumerable of yielded values.
    def values(path, body = nil, context = nil)
      sender.values(path, body, context)
    end

    # Connect to the hub. On every (re)connect: hub/profile/update (if a
    # profile is set), then hub/service/update with the current services+apps
    # (the hub drops a sender's services on disconnect). Each (re)connect
    # first asks the hub to prove its key (see #auth_headers). A plain ws://
    # address beyond loopback, the overlay and the LAN isn't dialed.
    def start
      @mutex.synchronize do
        return self if @sender

        @last_error = nil
        # channel-rb only knows ws:// and wss://: it would turn these into a plain ws:// address.
        if @address.to_s.match?(%r{\A(https|quic)://}i)
          @last_error = "#{target} would carry this service's key unencrypted: this client only encrypts wss://"
          warn "hub-service: #{@last_error}"
          return self
        end
        if !@allow_plaintext && HubServiceRB.hub_transport_of(@address) == 'refused'
          @last_error = "#{target} would carry this service's key unencrypted. Use wss://, " \
                        'or set :allow_plaintext (HUB_ALLOW_PLAINTEXT=1) on a private network'
          warn "hub-service: #{@last_error}"
          return self
        end
        # The client asks for headers on this thread first, then on a reconnect
        # thread of its own, and retries when they raise. Asking the hub can
        # take a while, so this first attempt goes straight to such a thread.
        starter = Thread.current
        @sender = @channel.connect(@address,
                                   on_connect: proc { |s| send_updates(s) },
                                   headers: lambda {
                                     raise Error, 'not on the caller of start' if Thread.current == starter

                                     auth_headers
                                   })
      end
      self
    end

    # Disconnect from the hub, ending a wait for its proof.
    def stop
      sender = @mutex.synchronize do
        current = @sender
        @sender = nil
        current
      end
      sender&.stop
      self
    end

    # The instance name sent in the certificate: the option, else
    # HUB_INSTANCE (the launcher sets it), else the name, else the cwd name,
    # else 'service'; at most 128 UTF-8 bytes.
    def instance
      name = [@instance, ENV['HUB_INSTANCE'], @profile && @profile[:name], File.basename(Dir.pwd)]
             .map(&:to_s).find { |value| !value.empty? } || 'service'
      name = name.byteslice(0, 128).scrub('')
      name.empty? ? 'service' : name
    end

    # The hubs.json pin key for this hub.
    def target
      HubServiceRB::Keychain.pin_address(@address)
    end

    # Pinned hub keys: +hubs.json+ beside the service key file.
    def pins
      HubPins.new(File.join(File.dirname(HubServiceRB::Keychain.key_path), 'hubs.json'))
    end

    # The hub key this service expects: supplied, else pinned, else nil until a
    # hub proved one. The pin is read from hubs.json at each connect and kept
    # in memory.
    def hub_key
      return @hub_key if @hub_key

      unless @pin_loaded
        @pinned = pins.get(target)
        @pin_loaded = true
      end
      @pinned
    end

    # Clear the pinned hub key; the next connect pins what the hub proves.
    def forget_hub_key
      @hub_key = nil
      @pinned = nil
      pins.forget(target)
    end

    # Runs before every connection attempt (protocol.md section 2), on the
    # client's reconnect thread. It comes back with a token over a fresh
    # challenge from a hub that proved its key; until one has, it holds the
    # attempt back, so nothing goes out and requests keep waiting. After a stop
    # it raises, which tells the client not to connect.
    def auth_headers
      client = @sender&.ws
      delay = HANDSHAKE_RETRY
      reported = nil
      loop do
        begin
          headers = handshake
          raise Error, 'stopped' if client && !client.running?

          @last_error = nil
          return headers
        rescue StandardError => e
          raise if client && !client.running?

          @last_error = e.message
          if @last_error != reported
            reported = @last_error
            warn "hub-service: #{reported}"
          end
        end
        wait_for_retry(client, delay)
        delay = [delay * 2, HANDSHAKE_MAX_RETRY].min
      end
    end

    # The key this service connects with (the key in its auth token).
    def service_key
      @service_key || HubServiceRB::Keychain.public_key
    end

    # Declare a Hub Network share before start: the declared set is published
    # on connect and after every reconnect. Default policy: private.
    def share(name, protocol, host, port, policy = nil)
      @network.declare_share(share_hash(name, protocol, host, port, policy))
      self
    end

    # Publish a local TCP/UDP port through Hub Network; returns every
    # publication ({'resourceId', 'authority', 'overlayAddress', 'port', ...}).
    def publish_share(name, protocol, host, port, policy = nil)
      @network.publish_share(share_hash(name, protocol, host, port, policy), service_key, @sign_challenge, sender)
    end

    # Change a share's policy or target port and republish it.
    def update_share(name, policy: nil, port: nil)
      current = @network.declared_shares.find { |s| s['name'] == name }
      raise KeyError, "Share '#{name}' not found" unless current

      updated = current.dup
      updated['policy'] = JSON.parse(JSON.generate(policy)) if policy
      updated['target'] = current['target'].merge('port' => port) if port
      @network.publish_share(updated, service_key, @sign_challenge, sender)
    end

    # Remove a share from Hub Network.
    def remove_share(name)
      @network.remove_share(name, service_key, @sign_challenge, sender)
    end

    def share_publications
      @network.publications
    end

    def share_publication(name)
      @network.publication(name)
    end

    # Build the current hub/service/update payload:
    # { services: [{path:, permissions?, limit?}...] (sorted by path), apps: [...] }
    def update
      services = []
      sorted_paths.each do |path|
        st = @settings[path] || {}
        entry = { path: path }
        permissions = build_permissions(st[:permissions], path)
        entry[:permissions] = permissions if permissions
        entry[:limit] = st[:limit] unless st[:limit].nil?
        services << entry
      end
      { services: services, apps: @apps }
    end

    private

    # Blocks drop arguments they don't name, so +{ |body| }+ keeps working;
    # a one-argument lambda gets the body alone.
    def call_handler(handler, payload)
      if handler.lambda? && handler.arity.between?(0, 1)
        handler.call(payload[:body])
      else
        handler.call(payload[:body], Request.from_payload(payload, hub_key))
      end
    end

    def sender
      @mutex.synchronize do
        raise Error, @last_error || 'Service not started' unless @sender

        @sender
      end
    end

    # Asks the hub for its proof and signs for that answer alone.
    def handshake
      begin
        proof = HubServiceRB.ask_hub(@address)
      rescue StandardError => e
        raise Error, "#{target}: #{e.message}, sending it nothing"
      end
      @pin_loaded = false # pick up a pin another process wrote
      pinned = hub_key
      if pinned.nil?
        pins.set(target, proof.key)
        @pinned = proof.key
        @pin_loaded = true
      elsif pinned != proof.key
        raise Error, "#{target} answers with key #{proof.key}, not the pinned #{pinned}, sending it nothing. " \
                     '#forget_hub_key if its key really changed'
      end
      token = @sign.call(proof.key, proof.challenge).to_s
      headers = { 'auth' => token, 'v' => HubServiceRB::Keychain::AUTH_VERSION }
      @service_key = token.split('.')[1]
      if @device
        begin
          # The certificate names the key in the token, whoever signed it.
          headers['device'] = @device.certificate(token.split('.')[1], instance)
        rescue StandardError
          nil # no readable or creatable device key: a plain key connection
        end
      end
      headers
    end

    # Sleeps until the next attempt, waking up soon after a stop.
    def wait_for_retry(client, delay)
      deadline = Time.now + delay
      sleep 0.05 while Time.now < deadline && (client.nil? || client.running?)
      raise Error, 'stopped' if client && !client.running?
    end

    def send_updates(s)
      send_untracked(s, 'hub/profile/update', @profile) if @profile
      send_untracked(s, 'hub/service/update', update)
      republish(s) if @network.shares?
    end

    # Republish the declared shares on their own thread (on_connect runs on
    # the iodine loop, where waiting for a response would deadlock).
    def republish(s)
      Thread.new do
        begin
          @network.republish_all(service_key, @sign_challenge, s)
        rescue StandardError => e
          warn "Failed to republish network shares: #{e.message}"
        end
      end
    end

    def share_hash(name, protocol, host, port, policy)
      { 'name' => name, 'protocol' => protocol.to_s, 'target' => { 'host' => host, 'port' => port },
        'policy' => policy ? JSON.parse(JSON.generate(policy)) : { 'mode' => 'private' } }
    end

    # Fire-and-forget send. on_connect runs on the iodine event-loop thread,
    # where a blocking request/response would deadlock; the hub endpoints don't
    # need a response (Go port parity: SendUntracked).
    def send_untracked(s, path, body)
      connection = s.instance_variable_get(:@connection)
      connection.notify(path: path, body: body)
    end

    def sorted_paths
      @mutex.synchronize { @paths.keys.sort }
    end

    def add_path(path, settings)
      @mutex.synchronize do
        @paths[path] = true
        next unless settings

        st = settings.dup
        perms = st[:permissions]
        if perms && (perms[:group].nil? || perms[:group].to_s.empty?)
          perms = st[:permissions] = perms.dup
          perms[:group] = path.split('/').first
        end
        @settings[path] = st
      end
    end

    # Rebuild permissions with deterministic key order (group, name, allows)
    # so the serialized payload matches the wire contract exactly.
    def build_permissions(p, path)
      return nil unless p

      result = {}
      group = p[:group].to_s.empty? ? path.split('/').first : p[:group]
      result[:group] = group if group
      result[:name] = p[:name] if p[:name]
      result[:allows] = p[:allows] unless p[:allows].nil?
      result.empty? ? nil : result
    end
  end
end
