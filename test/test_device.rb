# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'minitest/autorun'
require 'tmpdir'

require 'hub_service_rb'

# Device key file and service certificates (protocol.md §3).
class TestDevice < Minitest::Test
  Device = HubServiceRB::Device

  def setup
    @dir = Dir.mktmpdir('hubdevice-rb')
    @saved = ENV['HUB_DEVICE_KEY']
    ENV['HUB_DEVICE_KEY'] = File.join(@dir, 'hub', 'device.key')
    HubServiceRB::Keychain.key_path = File.join(@dir, 'auth')
  end

  def teardown
    ENV['HUB_DEVICE_KEY'] = @saved
    HubServiceRB::Keychain.key_path = nil
    FileUtils.remove_entry(@dir)
  end

  def decode(header)
    JSON.parse(Base64.urlsafe_decode64(header.split('.').first))
  end

  def test_key_path_override
    assert_equal File.join(@dir, 'hub', 'device.key'), Device.default_key_path
  end

  def test_key_file_created_private_and_reused
    key = Device.new.public_key
    path = File.join(@dir, 'hub', 'device.key')
    assert_equal 0o600, File.stat(path).mode & 0o777
    assert_equal 0o700, File.stat(File.dirname(path)).mode & 0o777
    assert_equal 92, Base64.strict_decode64(File.read(path)).bytesize
    assert_equal key, Device.new.public_key
    assert_equal ['device.key'], Dir.children(File.dirname(path))
  end

  def test_certificate_signed_by_device_over_payload
    device = Device.new(name: 'Mac Studio', platform: 'macos')
    header = device.certificate('SERVICE', 's3-local/Backup Disk', now: 1_792_500_000)
    payload, signature = header.split('.')
    verify_key = Ed25519::VerifyKey.new(Base64.strict_decode64(device.public_key).byteslice(12, 32))
    assert verify_key.verify(Base64.strict_decode64(signature), payload)
    body = decode(header)
    assert_equal %w[v device service instance deviceName platform iat exp], body.keys
    assert_equal Device::CERTIFICATE_LIFETIME, body['exp'] - body['iat']
  end

  def test_certificate_renewed_with_less_than_a_day_left
    device = Device.new
    first = device.certificate('SERVICE', 'echo', now: 1000)
    assert_equal first, device.certificate('SERVICE', 'echo', now: 1000 + 5 * 86_400)
    renewed = device.certificate('SERVICE', 'echo', now: 1000 + 6 * 86_400 + 1)
    refute_equal first, renewed
    assert_equal 1000 + 6 * 86_400 + 1 + Device::CERTIFICATE_LIFETIME, Device.certificate_expiry(renewed)
  end

  def test_service_sends_device_header_for_its_key
    service = HubServiceRB::Service.new(address: 1, instance: 'echo/main')
    headers = service.auth_headers
    body = decode(headers['device'])
    assert_equal HubServiceRB::Keychain.public_key, body['service']
    assert_equal headers['auth'].split('.')[1], body['service']
    assert_equal 'echo/main', body['instance']
    assert_equal service.device.public_key, body['device']
  end

  def test_instance_defaults
    assert_equal 'Echo', HubServiceRB::Service.new(name: 'Echo').instance
    service = HubServiceRB::Service.new
    assert_equal 'service', service.instance
    service.post('s3/read') { |body| body }
    service.post('echo') { |body| body }
    assert_equal 's3', service.instance
  end

  def test_instance_length_checked
    assert_raises(HubServiceRB::Error) { Device.new.certificate('SERVICE', 'x' * 129) }
  end

  def test_device_mode_off_sends_no_header
    refute HubServiceRB::Service.new(address: 1, device: false).auth_headers.key?('device')
    refute File.exist?(File.join(@dir, 'hub'))
  end

  def test_unreadable_device_key_falls_back_to_plain_key
    blocked = File.join(@dir, 'blocked')
    File.write(blocked, 'not a directory')
    ENV['HUB_DEVICE_KEY'] = File.join(blocked, 'device.key')
    headers = HubServiceRB::Service.new(address: 1).auth_headers
    refute headers.key?('device')
    assert headers['auth'].start_with?('key.')
  end
end
