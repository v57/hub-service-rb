# frozen_string_literal: true

module HubServiceRB
  # The caller's device, when its connection is device-attached.
  CallerDevice = Struct.new(:id, :name)

  # Who is calling, as the hub saw it (+context.hub.caller+,
  # Docs/Devices/protocol.md §4). +key+ is nil for anonymous callers,
  # +device+ nil for clients without one; +via+ and +claimed+ are set for
  # calls through a merged hub (+claimed+ is unverified).
  Caller = Struct.new(:key, :device, :groups, :owner, :via, :claimed) do
    def self.parse(value)
      return nil unless value.is_a?(Hash)

      device = Request.read(value, 'device')
      groups = Request.read(value, 'groups')
      new(
        string(Request.read(value, 'key')),
        device.is_a?(Hash) ? CallerDevice.new(Request.read(device, 'id').to_s, Request.read(device, 'name').to_s) : nil,
        groups.is_a?(Array) ? groups.select { |g| g.is_a?(String) } : [],
        Request.read(value, 'owner') == true,
        string(Request.read(value, 'via')),
        parse(Request.read(value, 'claimed'))
      )
    end

    def self.string(value)
      value.is_a?(String) ? value : nil
    end
  end

  # What a two-argument handler gets next to the body: the caller, the
  # request context without +hub+, and the called path. The caller is nil
  # unless the hub that forwarded the request is the pinned hub: a hub that
  # predates caller identity may pass a client's context.hub through.
  Request = Struct.new(:caller, :context, :path) do
    def self.from_payload(payload, hub_key)
      context = payload[:context].is_a?(Hash) ? payload[:context].dup : {}
      hub = context.delete('hub') || context.delete(:hub)
      trusted = hub.is_a?(Hash) && hub_key && read(hub, 'hubKey') == hub_key
      new(trusted ? Caller.parse(read(hub, 'caller')) : nil, context, payload[:path])
    end

    # Read a JSON key whether the hash has string or symbol keys.
    def self.read(hash, key)
      hash.key?(key) ? hash[key] : hash[key.to_sym]
    end
  end
end
