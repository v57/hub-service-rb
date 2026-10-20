# frozen_string_literal: true

require 'base64'
require 'digest'
require 'etc'
require 'json'
require 'open3'
require 'socket'

module HubServiceRB
  # Device key and service certificates (Docs/Devices/protocol.md).
  #
  # - The device key lives in +~/.hub/device.key+ (+/var/lib/hub/device.key+
  #   for a Linux system service, +HUB_DEVICE_KEY+ overrides both) in the same
  #   layout as the +auth+ file. It is created atomically on first use.
  # - A service certificate is +<base64url(JSON)>.<base64 signature>+, signed
  #   by the device key over the payload string, and sent in the +device+
  #   header. It names the service key, the instance and the device's
  #   suggested name.
  #
  # Usage:
  #
  #   device = HubServiceRB::Device.new            # ~/.hub/device.key
  #   header = device.certificate(service_key, 's3-local/Backup Disk')
  class Device
    # Certificates live up to 7 days and are renewed at connect with < 24 h left.
    CERTIFICATE_LIFETIME = 7 * 24 * 3600
    CERTIFICATE_RENEWAL = 24 * 3600

    class << self
      # +HUB_DEVICE_KEY+, else the system or user location.
      def default_key_path
        env = ENV['HUB_DEVICE_KEY']
        return env if env && !env.empty?
        return '/var/lib/hub/device.key' if RUBY_PLATFORM.include?('linux') && Process.euid.zero?

        File.join(Dir.home, '.hub', 'device.key')
      end

      # First 32 hex characters of SHA-256 over the device SPKI DER.
      def device_id(public_key)
        Digest::SHA256.hexdigest(Base64.strict_decode64(public_key))[0, 32]
      end

      # The code shown on both sides when approving a device: +"ddd ddd"+.
      def safety_code(public_key)
        n = Digest::SHA256.hexdigest(Base64.strict_decode64(public_key))[0, 8].to_i(16) % 1_000_000
        format('%03d %03d', n / 1000, n % 1000)
      end

      def default_platform
        case RUBY_PLATFORM
        when /darwin/ then 'macos'
        when /linux/ then 'linux'
        when /mswin|mingw|cygwin/ then 'windows'
        else 'other'
        end
      end

      # The macOS computer name, else the host name.
      def default_name
        if RUBY_PLATFORM.include?('darwin')
          begin
            name, status = Open3.capture2('scutil', '--get', 'ComputerName', err: File::NULL)
            return name.strip if status.success? && !name.strip.empty?
          rescue StandardError
            nil
          end
        end
        name = Socket.gethostname.to_s
        name = 'device' if name.empty?
        name.sub(/\.local\z/, '')
      end

      # A service certificate from device key file bytes, fields in protocol
      # order with no whitespace.
      def certificate(device_key, service:, instance:, iat:, exp:, device_name: nil, platform: nil, parent: nil)
        raise Error, 'instance must be 1-128 UTF-8 bytes' unless (1..128).cover?(instance.bytesize)
        raise Error, 'parent must be at most 64 UTF-8 bytes' if parent && parent.bytesize > 64

        payload = { v: 1, device: Keychain.spki(device_key), service: service, instance: instance }
        payload[:deviceName] = device_name unless device_name.nil?
        payload[:platform] = platform unless platform.nil?
        payload[:parent] = parent unless parent.nil?
        payload[:iat] = iat
        payload[:exp] = exp
        encoded = Base64.urlsafe_encode64(JSON.generate(payload), padding: false)
        signature = Base64.strict_encode64(Keychain.signing_key_for(device_key).sign(encoded))
        "#{encoded}.#{signature}"
      end

      # The +exp+ of a certificate header.
      def certificate_expiry(header)
        JSON.parse(Base64.urlsafe_decode64(header.split('.', 2).first))['exp']
      end
    end

    attr_reader :platform, :parent

    # path: the key file (default: Device.default_key_path); key: key file
    # bytes to use instead of a file (tests, or a key kept in another store);
    # name: suggested device name (default: the computer name); platform:
    # protocol platform string (default: from the OS); parent: declared
    # parent device name, for containers and VMs.
    def initialize(path: nil, key: nil, name: nil, platform: nil, parent: nil)
      @path = path
      @key = key
      @name = name
      @platform = platform || self.class.default_platform
      @parent = parent
      @certificates = {}
      @mutex = Mutex.new
    end

    # Device key file bytes, loaded or created on first use.
    def key
      @key ||= Keychain.load_key_file(@path || self.class.default_key_path, private: true)
    end

    def name
      @name ||= truncate(self.class.default_name, 64)
    end

    def public_key
      Keychain.spki(key)
    end

    def id
      self.class.device_id(public_key)
    end

    def safety_code
      self.class.safety_code(public_key)
    end

    # The certificate for a service key, renewed with < 24 h left.
    def certificate(service, instance, now: Time.now.to_i)
      @mutex.synchronize do
        cached = @certificates[[service, instance]]
        return cached if cached && self.class.certificate_expiry(cached) - now >= CERTIFICATE_RENEWAL

        @certificates[[service, instance]] = self.class.certificate(
          key, service: service, instance: instance, iat: now, exp: now + CERTIFICATE_LIFETIME,
               device_name: name, platform: platform, parent: parent
        )
      end
    end

    private

    # At most limit UTF-8 bytes, cut on a character boundary.
    def truncate(text, limit)
      text.byteslice(0, limit).scrub('')
    end
  end
end
