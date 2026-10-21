# frozen_string_literal: true

require 'fileutils'
require 'minitest/autorun'
require 'tmpdir'

# Keep every test off the real ~/.hub/device.key.
device_dir = Dir.mktmpdir('hub-device-rb')
ENV['HUB_DEVICE_KEY'] = File.join(device_dir, 'device.key')
Minitest.after_run { FileUtils.remove_entry(device_dir) }
require_relative 'test_service'
require_relative 'test_keychain'
require_relative 'test_auth'
require_relative 'test_device'
require_relative 'test_caller'
require_relative 'test_vectors'
require_relative 'test_network'
