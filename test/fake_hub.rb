# frozen_string_literal: true

require 'base64'
require 'json'
require 'minitest'
require 'socket'
require 'hub_service_rb'

# One in-process hub for the live tests: iodine runs a single runtime per
# process and stopping a server stops it, so every test shares this one.
# It records the headers of each connect and answers hub/info with a proof and
# a fresh challenge per question, unless a test sets another answer.
module FakeHub
  VECTORS = JSON.parse(File.read(File.expand_path('../../../Docs/Devices/vectors.json', __dir__)))
  HUB_KEY = VECTORS['keys']['hub']['publicKey']

  class << self
    attr_accessor :answer, :on_update
    attr_reader :port, :updates

    # An answer that proves the key of a vector key.
    def proving(name = 'hub')
      bytes = HubServiceRB::Keychain.decode_key_file(VECTORS['keys'][name]['keyFile'])
      public_key = VECTORS['keys'][name]['publicKey']
      lambda do |nonce, challenge|
        signed = HubServiceRB.hub_info_signed_data(public_key, nonce)
        { key: public_key, protocol: 2, challenge: challenge,
          proof: Base64.strict_encode64(HubServiceRB::Keychain.signing_key_for(bytes).sign(signed)) }
      end
    end

    # The connects that carried credentials.
    def credentials
      headers.select { |h| h.key?('auth') || h.key?('device') }
    end

    def wait_updates(count, seconds = 5)
      deadline = Time.now + seconds
      sleep 0.02 while @updates < count && Time.now < deadline
      raise "expected #{count} service updates, got #{@updates}" if @updates < count
    end

    def headers
      @mutex.synchronize { @headers.dup }
    end

    # network/shares/replace bodies received.
    def replaced
      @mutex.synchronize { @replaced.dup }
    end

    def reset
      @mutex.synchronize do
        @headers = []
        @replaced = []
      end
      @answer = proving
      @on_update = nil
      @updates = 0
      @asked = 0
    end

    def start
      return if @port

      @mutex = Mutex.new
      reset
      server = TCPServer.new('127.0.0.1', 0)
      @port = server.addr[1]
      server.close
      channel = ChannelRB::Channel.new
      channel.post('hub/info') do |payload|
        @asked += 1
        FakeHub.answer.call(payload[:body]['nonce'], "challenge-#{@asked}")
      end
      channel.post('hub/profile/update') { nil }
      channel.post('test/echo') { |payload| payload[:body] }
      channel.post('network/shares/replace') do |payload|
        body = payload[:body]
        @mutex.synchronize { @replaced << body }
        { 'shares' => body['shares'].map do |share|
          { 'version' => 1, 'resourceId' => "hnr1_#{share['name']}", 'authority' => "#{share['name']}.hub.invalid",
            'providerId' => 'provider', 'protocol' => share['protocol'], 'overlayAddress' => '100.96.0.2',
            'port' => share['target']['port'] }
        end }
      end
      channel.post('hub/service/update') do |payload|
        @updates += 1
        callback = FakeHub.on_update
        Thread.new { callback.call(payload[:sender]) } if callback
        nil
      end
      channel.listen("127.0.0.1:#{@port}", state: proc { |headers|
        @mutex.synchronize { @headers << headers }
        {}
      })
      wait_for_port
      # channel_rb's at_exit stop runs before Minitest's (LIFO), so stop the
      # runtime this hub started once the tests are done.
      Minitest.after_run { ChannelRB::IodineRuntime.stop }
    end

    def wait_connects(count, seconds = 5)
      deadline = Time.now + seconds
      sleep 0.02 while headers.length < count && Time.now < deadline
      raise "expected #{count} connects, got #{headers.length}" if headers.length < count
    end

    private

    def wait_for_port
      50.times do
        begin
          Socket.tcp('127.0.0.1', @port, connect_timeout: 1, &:close)
          return
        rescue StandardError
          sleep 0.05
        end
      end
    end
  end
end
