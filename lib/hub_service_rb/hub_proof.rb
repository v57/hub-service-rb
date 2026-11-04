# frozen_string_literal: true

require 'base64'
require 'ed25519'
require 'securerandom'
require 'timeout'

module HubServiceRB
  # Auth v2's client side (Docs/Devices/protocol.md section 2): before every
  # connect the service asks hub/info on an anonymous connection with a fresh
  # nonce, and sends its token only if the hub proved the key it claims, over
  # that nonce.
  HUB_ADDRESS = %r{\A([a-zA-Z][a-zA-Z0-9+.-]*)://(?:[^/?#@]*@)?(\[[^\]]*\]|[^/?#:]*)}.freeze
  # How long one hub/info question may take before a connect.
  HUB_INFO_TIMEOUT = 5

  # An answer to hub/info whose proof checked out.
  HubProof = Struct.new(:key, :challenge)

  class << self
    # How a connection to an address travels: 'encrypted', 'loopback',
    # 'overlay', 'localNetwork', or 'refused' (plain ws:// beyond those, not
    # dialed unless :allow_plaintext says so). Nothing is dialed to find out.
    def hub_transport_of(address)
      return 'loopback' if address.is_a?(Integer) || address.to_s.match?(/\A\d+\z/)

      match = address.to_s.match(HUB_ADDRESS)
      return 'refused' unless match

      scheme = match[1].downcase
      host = match[2].downcase.delete_suffix('.')
      return 'encrypted' if %w[wss https quic].include?(scheme)
      return 'refused' unless %w[ws http].include?(scheme)
      return transport_of_ipv6(host[1...-1]) if host.start_with?('[')

      v4 = ipv4(host)
      return transport_of_ipv4(*v4) if v4
      return 'loopback' if host == 'localhost' || host.end_with?('.localhost')
      return 'overlay' if host.end_with?('.hub.invalid')
      return 'localNetwork' if host.end_with?('.local')

      'refused'
    end

    # The nonce for one hub/info: 32 fresh random bytes in base64url.
    def make_client_nonce
      SecureRandom.urlsafe_base64(32)
    end

    # The string a hub/info proof signs.
    def hub_info_signed_data(hub_key, nonce)
      "hubinfo1:#{hub_key}:#{nonce}"
    end

    # Whether a hub/info answer proves its key over +nonce+. A relayed answer
    # passes too, so it never decides which credentials a hub gets.
    def verify_hub_proof(info, nonce)
      return false unless info.is_a?(Hash)

      key = info['key']
      proof = info['proof']
      return false unless key.is_a?(String) && proof.is_a?(String) && info['challenge'].is_a?(String)

      spki = Base64.strict_decode64(key)
      return false unless spki.bytesize == 44 && spki.start_with?(Keychain::SPKI_PREFIX)

      Ed25519::VerifyKey.new(spki.byteslice(12, 32)).verify(Base64.strict_decode64(proof), hub_info_signed_data(key, nonce))
      true
    rescue ArgumentError, Ed25519::VerifyError
      false
    end

    # Asks the hub at +address+ for its key and a challenge, on a short
    # anonymous connection, and returns the answer only with a valid proof.
    def ask_hub(address, timeout = HUB_INFO_TIMEOUT)
      nonce = make_client_nonce
      probe = ChannelRB::Channel.new.connect(address)
      begin
        info = Timeout.timeout(timeout, Timeout::Error, 'hub/info timed out') { probe.send('hub/info', { nonce: nonce }) }
      ensure
        close_probe(probe)
      end
      raise Error, "hub didn't prove its key" unless verify_hub_proof(info, nonce)

      HubProof.new(info['key'], info['challenge'])
    end

    private

    # Waits for the probe to be closed: a connect iodine starts while the last one is still closing
    # ends without sending anything, and that connect is the real one.
    def close_probe(probe)
      closed = Queue.new
      open = probe.ws.connected?
      probe.ws.on_close = -> { closed << true }
      probe.stop
      return unless open

      begin
        Timeout.timeout(1) { closed.pop }
      rescue Timeout::Error
        nil
      end
    end

    def ipv4(host)
      parts = host.split('.', -1)
      return nil unless parts.length == 4 && parts.all? { |part| part.match?(/\A\d{1,3}\z/) }

      bytes = parts.map(&:to_i)
      bytes.all? { |byte| byte <= 255 } ? bytes : nil
    end

    def transport_of_ipv4(first, second, *)
      return 'loopback' if first == 127
      return 'overlay' if first == 100 && second.between?(64, 127)
      return 'localNetwork' if first == 10 || (first == 172 && second.between?(16, 31)) ||
                               (first == 192 && second == 168) || (first == 169 && second == 254)

      'refused'
    end

    def transport_of_ipv6(host)
      return 'loopback' if host == '::1'
      return 'localNetwork' if host.match?(/\A(f[cd]|fe[89ab])/)

      'refused'
    end
  end
end
