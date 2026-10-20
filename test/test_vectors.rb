# frozen_string_literal: true

require 'json'
require 'minitest/autorun'

require 'hub_service_rb'

# Docs/Devices/vectors.json: every string must match exactly.
class TestVectors < Minitest::Test
  VECTORS = JSON.parse(File.read(File.expand_path('../../../Docs/Devices/vectors.json', __dir__)))
  KEYS = VECTORS['keys']
  Keychain = HubServiceRB::Keychain
  Device = HubServiceRB::Device

  def key(name)
    Keychain.decode_key_file(KEYS[name]['keyFile'])
  end

  def test_key_files_and_public_keys
    %w[hub service device].each do |name|
      assert_equal KEYS[name]['publicKey'], Keychain.spki(key(name))
      seed = [KEYS[name]['seed']].pack('H*')
      assert_equal KEYS[name]['keyFile'], Base64.strict_encode64(Keychain.key_file_bytes(seed))
    end
  end

  def test_device_id_and_safety_code
    assert_equal KEYS['device']['deviceId'], Device.device_id(KEYS['device']['publicKey'])
    assert_equal KEYS['device']['safetyCode'], Device.safety_code(KEYS['device']['publicKey'])
  end

  def test_auth_tokens
    auth = VECTORS['auth']
    assert_equal auth['v0']['header'], Keychain.token(key('service'), auth['expiry'])
    assert_equal auth['v1']['header'], Keychain.token(key('service'), auth['expiry'], KEYS['hub']['publicKey'])
  end

  def test_certificates
    cert = VECTORS['certificate']
    header = Device.certificate(key('device'), service: KEYS['service']['publicKey'], instance: 's3-local/Backup Disk',
                                               iat: 1_792_500_000, exp: 1_793_104_800,
                                               device_name: 'Mac Studio', platform: 'macos')
    assert_equal cert['header'], header
    assert_equal cert['payload'], header.split('.').first
    child = Device.certificate(key('device'), service: KEYS['service']['publicKey'], instance: 'builder',
                                              iat: 1_792_500_000, exp: 1_793_104_800,
                                              device_name: 'builder', platform: 'linux', parent: 'Mac Studio')
    assert_equal VECTORS['childCertificate']['header'], child
  end

  def test_device_issues_the_vector_certificate
    device = Device.new(key: key('device'), name: 'Mac Studio', platform: 'macos')
    assert_equal KEYS['device']['deviceId'], device.id
    header = device.certificate(KEYS['service']['publicKey'], 's3-local/Backup Disk', now: 1_792_500_000)
    assert_equal VECTORS['certificate']['header'], header
  end
end
