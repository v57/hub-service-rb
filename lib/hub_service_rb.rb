# frozen_string_literal: true

# hub-service-rb: Ruby port of hub-service (TS reference).
# Connects with hub-pro auth (keychain + signed tokens) when available;
# hub-lite ignores the auth headers entirely (regression-safe).

# channel-rb is a sibling checkout (no gemspec), wired via the monorepo layout.
# If channel_rb is already available as a gem, the load path stays untouched.
unless $LOAD_PATH.any? { |p| p.end_with?('/channel-rb/lib') }
  $LOAD_PATH.unshift(File.expand_path('../../../Channel/channel-rb/lib', __dir__))
end

require 'thread'
require 'channel_rb'
require 'hub_service_rb/app'
require 'hub_service_rb/keychain'

module HubServiceRB
  # Raised when calling the hub before the service is started.
  class Error < StandardError; end

  # Service registers API endpoints on a hub and serves calls forwarded by it.
  class Service
    attr_reader :apps, :profile

    # options: :address (port or ws:// URL; default 1997 or $HUB), :name, :icon
    # (string or {symbol:, text:}), :sign (callable returning a fresh hub-pro
    # auth token; default: the keychain +auth+ file in the cwd, TS parity).
    def initialize(options = {})
      hub = ENV['HUB']
      hub = hub&.match?(/\A\d+\z/) ? hub.to_i : hub
      @address = options[:address] || hub || 1997
      @sign = options[:sign] || -> { HubServiceRB::Keychain.sign }
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
    # request body and its return value is the response.
    def post(path, settings = nil, &handler)
      add_path(path, settings)
      @channel.post(path) { |payload| handler.call(payload[:body]) }
      self
    end

    # Register a streaming API endpoint. The handler receives the request body
    # and must return an enumerable of values (Enumerator, Array, ...).
    def stream(path, settings = nil, &handler)
      add_path(path, settings)
      @channel.stream(path) { |payload| handler.call(payload[:body]) }
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
    # also carries fresh hub-pro auth headers ({auth: <signed token>, v: '0'})
    # — the client URL-encodes them as query params on the ws:// handshake.
    def start
      @mutex.synchronize do
        return self if @sender

        @sender = @channel.connect(@address,
                                   on_connect: proc { |s| send_updates(s) },
                                   headers: -> { auth_headers })
      end
      self
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

    def sender
      @mutex.synchronize do
        raise Error, 'Service not started' unless @sender

        @sender
      end
    end

    def send_updates(s)
      send_untracked(s, 'hub/profile/update', @profile) if @profile
      send_untracked(s, 'hub/service/update', update)
    end

    # Fresh hub-pro auth headers for every (re)connect: a freshly signed
    # token + protocol version (TS reference parity). The channel client
    # calls this once per connection attempt (initial + reconnects) and
    # sends them as real WebSocket handshake headers (never in the URL).
    # hub-lite ignores them (regression-safe).
    def auth_headers
      { 'auth' => @sign.call.to_s, 'v' => '0' }
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
