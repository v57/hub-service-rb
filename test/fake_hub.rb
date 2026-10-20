# frozen_string_literal: true

require 'minitest'
require 'socket'
require 'hub_service_rb'

# One in-process hub for the live tests: iodine runs a single runtime per
# process and stopping a server stops it, so every test shares this one.
# It records the headers of each connect and answers hub/info unless lite.
module FakeHub
  HUB_KEY = 'MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w='

  class << self
    attr_accessor :lite, :on_update
    attr_reader :port

    def headers
      @mutex.synchronize { @headers.dup }
    end

    def reset
      @mutex.synchronize { @headers = [] }
      @lite = false
      @on_update = nil
    end

    def start
      return if @port

      @mutex = Mutex.new
      reset
      server = TCPServer.new('127.0.0.1', 0)
      @port = server.addr[1]
      server.close
      channel = ChannelRB::Channel.new
      channel.post('hub/info') do
        raise 'api not found' if FakeHub.lite

        { key: HUB_KEY, protocol: 1, pro: true, mode: 'default-allow' }
      end
      channel.post('hub/profile/update') { nil }
      channel.post('hub/service/update') do |payload|
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
