# frozen_string_literal: true

require 'base64'
require 'ed25519'
require 'fileutils'
require 'json'
require 'openssl'
require 'securerandom'
require 'tempfile'
require 'uri'

module HubServiceRB
  # ed25519 keychain: load-or-generate the +auth+ key file and sign tokens.
  #
  # Hub-pro auth parity with the TS reference (hub-service/keychain.ts):
  #
  # - The key file (+auth+ in the working directory, matching the TS
  #   keychain) is the base64 encoding of the 48-byte PKCS8 DER ed25519
  #   private key followed by the 44-byte SPKI DER public key (92 bytes
  #   total, 124 base64 chars).
  # - A signed token has the shape +key.<pub>.<sig>.<expiry>+ where:
  #     pub     = base64 of the 44-byte SPKI public key (bytes 48..92)
  #     sig     = base64 ed25519 signature over the signed data
  #     expiry  = DECIMAL epoch-seconds string of now + 60 (protocol
  #               default; hub-pro rejects it once expired or over 5
  #               minutes ahead)
  # - The signed data depends on the +v+ header (Docs/Devices/protocol.md):
  #     v: 0    the expiry string alone
  #     v: 1    +hub1:<hub key>:<expiry>+, so the token only works on the
  #             hub whose key it names
  # - The hub verifies the signature against the embedded public key and
  #   treats the key as the connection identity (owner/host/group).
  # - Hub keys learned from +hub/info+ are pinned in +hubs.json+ beside the
  #   key file: +{"<address>": "<hub SPKI>"}+ (see HubPins).
  #
  # Crypto backend: system ruby's openssl stdlib (LibreSSL) has no
  # OpenSSL::PKey::ED25519, so signing uses the RubyCrypto +ed25519+ gem
  # (RFC 8032, C reference implementation). The key file layout is
  # identical to the TS/Python ports either way.
  module Keychain
    # TS keychain layout: PKCS8 DER private key (48 bytes for ed25519)
    # followed by the SPKI DER public key (44 bytes for ed25519).
    PRIVATE_DER_LENGTH = 48
    PUBLIC_DER_LENGTH = 44

    # Fixed DER prefixes for ed25519 keys (RFC 8410):
    # PKCS8: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
    #                   OCTET STRING { OCTET STRING { 32-byte seed } } }
    # SPKI:  SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { pub } }
    PKCS8_PREFIX = "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20".b
    SPKI_PREFIX = "\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00".b

    class << self
      # Override the key file location (default: +auth+ in the cwd, or $HUBKEY).
      def key_path=(path)
        @key_path = path
        @key_bytes = nil
      end

      def key_path
        @key_path || ENV['HUBKEY'] || 'auth'
      end

      # The service's public key: base64 of the 44-byte SPKI DER.
      def public_key
        Base64.strict_encode64(public_der)
      end

      # A fresh auth token: +key.<pub>.<sig>.<expiry>+. With +hub_key+ (the
      # pinned hub key) it signs +hub1:<hub key>:<expiry>+ for +v: 1+;
      # without it the token is v0 (the expiry alone).
      def sign(expires = 60, hub_key: nil)
        token(key_bytes, Time.now.to_i + expires, hub_key)
      end

      # An auth token for an exact expiry from key file bytes.
      def token(bytes, expiry, hub_key = nil)
        data = hub_key ? "hub1:#{hub_key}:#{expiry}" : expiry.to_s
        signature = signing_key_for(bytes).sign(data)
        "key.#{spki(bytes)}.#{Base64.strict_encode64(signature)}.#{expiry}"
      end

      # The public half of key file bytes: base64 of the 44-byte SPKI DER.
      def spki(bytes)
        Base64.strict_encode64(bytes.byteslice(PRIVATE_DER_LENGTH, PUBLIC_DER_LENGTH))
      end

      # Key file bytes from its base64 text.
      def decode_key_file(text, path = 'key file')
        data = Base64.strict_decode64(text.strip)
        expected = PRIVATE_DER_LENGTH + PUBLIC_DER_LENGTH
        unless data.bytesize == expected
          raise Error, "bad auth file #{path}: expected #{expected} bytes, got #{data.bytesize}"
        end

        data
      end

      # Key file bytes for a 32-byte seed (TS layout).
      def key_file_bytes(seed)
        public_raw = Ed25519::SigningKey.new(seed).verify_key.to_bytes
        PKCS8_PREFIX + seed + SPKI_PREFIX + public_raw
      end

      # Load a key file, creating it if missing. +private: true+ creates it
      # atomically with mode 0600 inside a 0700 directory (device keys).
      def load_key_file(path, private: false)
        return decode_key_file(File.read(path), path) if File.exist?(path)

        data = key_file_bytes(SecureRandom.random_bytes(32))
        unless private
          File.write(path, Base64.strict_encode64(data))
          return data
        end
        dir = File.dirname(path)
        FileUtils.mkdir_p(dir, mode: 0o700)
        temp = Tempfile.create('.device.', dir) # mode 0600
        begin
          temp.write(Base64.strict_encode64(data))
          temp.close
          # link, not rename: a key another process created first wins.
          File.link(temp.path, path)
        rescue Errno::EEXIST
          return decode_key_file(File.read(path), path)
        ensure
          File.unlink(temp.path) if File.exist?(temp.path)
        end
        data
      end

      # Ed25519 signing key for key file bytes.
      def signing_key_for(bytes)
        Ed25519::SigningKey.new(seed_from_pkcs8(bytes.byteslice(0, PRIVATE_DER_LENGTH)))
      end

      # The hubs.json key for a hub address: a bare port is
      # +ws://localhost:<port>+; a URL keeps its form with the scheme and host
      # lowercased and no trailing slash (channel TS normalization).
      def pin_address(address)
        return "ws://localhost:#{address}" if address.is_a?(Integer) || address.to_s.match?(/\A\d+\z/)

        url = address.to_s
        match = url.match(%r{\A([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)(.*)\z}m)
        if match
          authority = match[2]
          user, at, host = authority.rpartition('@')
          authority = at.empty? ? authority.downcase : "#{user}@#{host.downcase}"
          url = "#{match[1].downcase}://#{authority}#{match[3]}"
        end
        url.sub(%r{/+\z}, '')
      end

      # Forget the cached key material (used by tests / key_path=).
      def reset!
        @key_bytes = nil
      end

      private

      def public_der
        key_bytes.byteslice(PRIVATE_DER_LENGTH, PUBLIC_DER_LENGTH)
      end

      def key_bytes
        @key_bytes ||= load_key_file(key_path)
      end

      # Extract the 32-byte raw seed from the PKCS8 DER private key.
      def seed_from_pkcs8(der)
        outer = OpenSSL::ASN1.decode(der)
        octets = outer.value[2]
        unless octets.tag == OpenSSL::ASN1::OCTET_STRING
          raise Error, 'bad auth file: PKCS8 private key has unexpected structure'
        end

        seed = OpenSSL::ASN1.decode(octets.value).value
        unless seed.bytesize == 32
          raise Error, "bad auth file: expected 32-byte ed25519 seed, got #{seed.bytesize}"
        end

        seed
      end
    end
  end

  # Hub keys pinned per address in +hubs.json+ (beside the key file).
  class HubPins
    attr_reader :path

    def initialize(path)
      @path = path
    end

    def get(address)
      value = load[address]
      value.is_a?(String) ? value : nil
    end

    def set(address, hub_key)
      pins = load
      pins[address] = hub_key
      write(pins)
    end

    def forget(address)
      pins = load
      write(pins) unless pins.delete(address).nil?
    end

    private

    def load
      data = JSON.parse(File.read(@path))
      data.is_a?(Hash) ? data : {}
    rescue Errno::ENOENT, JSON::ParserError
      {}
    end

    def write(pins)
      dir = File.dirname(@path)
      FileUtils.mkdir_p(dir)
      temp = Tempfile.create('.hubs.', dir)
      temp.write(JSON.pretty_generate(pins))
      temp.close
      File.rename(temp.path, @path)
    end
  end
end
