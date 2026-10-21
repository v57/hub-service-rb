# frozen_string_literal: true

require 'fileutils'
require 'minitest/autorun'
require 'tmpdir'

require 'hub_service_rb'
require 'hub_service_rb/keychain'

# Keychain unit tests: token shape, signature verification, auth file
# round-trip, and TS-generated auth file parity (hub-pro-support contract).
class TestKeychain < Minitest::Test
  # TS-generated test key (owner key from the hub-server test env) and its
  # public key (hub-service/keychain.ts parity).
  TS_TEST_AUTH = 'MC4CAQAwBQYDK2VwBCIEINguo0cc0FACJ0oRV3V/+ZqIyj04ON5wdMJGH4a/do8CMCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ='
  TS_TEST_PUB = 'MCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ='

  def setup
    @dir = Dir.mktmpdir('hubkey-rb')
    HubServiceRB::Keychain.key_path = File.join(@dir, 'auth')
  end

  def teardown
    HubServiceRB::Keychain.reset!
    HubServiceRB::Keychain.key_path = nil
    FileUtils.remove_entry(@dir)
  end

  def test_default_key_path_is_auth_in_cwd
    HubServiceRB::Keychain.key_path = nil
    ENV['HUBKEY'] = nil
    assert_equal 'auth', HubServiceRB::Keychain.key_path
  ensure
    ENV['HUBKEY'] = nil
  end

  def test_hubkey_env_overrides_key_path
    HubServiceRB::Keychain.key_path = nil
    ENV['HUBKEY'] = File.join(@dir, 'env-key')
    assert_equal ENV['HUBKEY'], HubServiceRB::Keychain.key_path
  ensure
    ENV['HUBKEY'] = nil
  end

  def test_generates_auth_file_and_round_trips
    pub1 = HubServiceRB::Keychain.public_key
    path = HubServiceRB::Keychain.key_path
    assert File.exist?(path), 'auth file should be generated on first use'
    # 92 bytes (48 PKCS8 + 44 SPKI) -> 124 base64 chars, no trailing newline.
    assert_equal 124, File.read(path).bytesize

    # Reload from disk: same public key (file round-trip).
    HubServiceRB::Keychain.reset!
    assert_equal pub1, HubServiceRB::Keychain.public_key
    assert_equal pub1, HubServiceRB::Keychain.sign.split('.')[1]
  end

  def test_token_shape_key_pub_sig_decimal
    token = HubServiceRB::Keychain.sign
    parts = token.split('.')
    assert_equal 4, parts.length, "token should be key.<pub>.<sig>.<expiry>: #{token}"
    assert_equal 'key', parts[0]
    assert_match(/\A[A-Za-z0-9+\/=]+\z/, parts[1], 'pub must be base64')
    assert_equal 60, parts[1].bytesize, 'pub is base64 of the 44-byte SPKI DER'
    assert_match(/\A[A-Za-z0-9+\/=]+\z/, parts[2], 'sig must be base64')
    assert_equal 88, parts[2].bytesize, 'sig is base64 of the 64-byte ed25519 signature'
    assert_match(/\A\d+\z/, parts[3], 'expiry must be a decimal string')
    assert_includes (Time.now.to_i + 58)..(Time.now.to_i + 62), parts[3].to_i
  end

  def test_signature_verifies_against_embedded_public_key
    token = HubServiceRB::Keychain.sign
    _key, pub_b64, sig_b64, expiry = token.split('.')
    assert_equal HubServiceRB::Keychain.public_key, pub_b64

    verify_key = Ed25519::VerifyKey.new(spki_raw_public_key(pub_b64))
    # The ed25519 gem raises on a bad signature rather than returning false.
    assert verify_key.verify(Base64.strict_decode64(sig_b64), expiry),
           'signature must verify over the expiry string with the token pub'
    assert_raises(Ed25519::VerifyError) do
      verify_key.verify(Base64.strict_decode64(sig_b64), "#{expiry}x")
    end
  end

  def test_ts_generated_auth_file_reproduces_public_key
    File.write(HubServiceRB::Keychain.key_path, TS_TEST_AUTH)
    HubServiceRB::Keychain.reset!

    assert_equal TS_TEST_PUB, HubServiceRB::Keychain.public_key,
                 'must reproduce the TS keychain public key from its auth file'

    token = HubServiceRB::Keychain.sign
    _key, pub_b64, sig_b64, expiry = token.split('.')
    assert_equal TS_TEST_PUB, pub_b64
    verify_key = Ed25519::VerifyKey.new(spki_raw_public_key(pub_b64))
    assert verify_key.verify(Base64.strict_decode64(sig_b64), expiry),
           'token signed with the TS key must verify against the TS public key'
  end

  def test_sign_accepts_custom_expiry
    token = HubServiceRB::Keychain.sign(60)
    expiry = token.split('.')[3].to_i
    assert_includes (Time.now.to_i + 58)..(Time.now.to_i + 62), expiry
  end

  def test_bad_auth_file_raises
    File.write(HubServiceRB::Keychain.key_path, 'bm90LWEta2V5') # "not-a-key"
    HubServiceRB::Keychain.reset!
    assert_raises(HubServiceRB::Error) { HubServiceRB::Keychain.public_key }
  end

  private

  # The token pub is the 44-byte SPKI DER; the raw 32-byte ed25519 public
  # key is the trailing 32 bytes (12-byte SPKI prefix, RFC 8410).
  def spki_raw_public_key(pub_b64)
    spki = Base64.strict_decode64(pub_b64)
    assert_equal 44, spki.bytesize
    raw = spki.byteslice(12, 32)
    assert_equal 32, raw.bytesize
    raw
  end
end
