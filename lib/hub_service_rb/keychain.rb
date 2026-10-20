# frozen_string_literal: true

require 'base64'
require 'ed25519'
require 'openssl'
require 'securerandom'

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
  #     sig     = base64 ed25519 signature over the expiry string
  #     expiry  = DECIMAL epoch-seconds string of now + 10 (TS parity;
  #               hub-pro rejects it once expired or if over 5 minutes
  #               ahead)
  # - The hub verifies the signature against the embedded public key and
  #   treats the key as the connection identity (owner/host/group).
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

      # A fresh auth token: +key.<pub>.<sig>.<expiry>+.
      def sign(expires = 10)
        expiry = (Time.now.to_i + expires).to_s
        signature = signing_key.sign(expiry)
        "key.#{public_key}.#{Base64.strict_encode64(signature)}.#{expiry}"
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
        @key_bytes ||= File.exist?(key_path) ? load_bytes : generate!
      end

      def load_bytes
        data = Base64.strict_decode64(File.read(key_path).strip)
        expected = PRIVATE_DER_LENGTH + PUBLIC_DER_LENGTH
        unless data.bytesize == expected
          raise Error, "bad auth file #{key_path}: expected #{expected} bytes, got #{data.bytesize}"
        end

        data
      end

      def generate!
        seed = SecureRandom.random_bytes(32)
        public_raw = Ed25519::SigningKey.new(seed).verify_key.to_bytes
        data = PKCS8_PREFIX + seed + SPKI_PREFIX + public_raw
        File.write(key_path, Base64.strict_encode64(data))
        data
      end

      def signing_key
        seed = seed_from_pkcs8(key_bytes.byteslice(0, PRIVATE_DER_LENGTH))
        Ed25519::SigningKey.new(seed)
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
end
