# frozen_string_literal: true

require 'json'
require 'socket'
require 'time'
require 'timeout'

module HubServiceRB
  # Hub Network share publication (TS network.ts parity).
  #
  # A share makes a local TCP/UDP port reachable through Hub Network. For each
  # declared share the service asks the local hub-net agent (HTTP over its Unix
  # socket) for an attestation: +/challenge+ returns a nonce, the service signs
  # it with its key, and +/attest+ returns the agent-signed attestation. The
  # complete declared set then goes to the hub in one +network/shares/replace+
  # call, which answers with one publication per share in request order. The set
  # is republished after every reconnect.
  module Network
    WIRE_VERSION = 1
    AGENT_SOCKET = '/var/run/hub-net/agent.sock'
    MAX_SHARE_NAME_LENGTH = 255
    CONTROL = /[\x00-\x1f\x7f]/.freeze

    # The local hub-net agent was unavailable, refused or answered badly.
    # +code+: agent-unavailable, agent-timeout, agent-rejected,
    # invalid-agent-response, attestation-mismatch, attestation-expired.
    class LocalAgentError < StandardError
      attr_reader :code, :status

      def initialize(code, message, status = nil)
        super(message)
        @code = code
        @status = status
      end
    end

    module_function

    def string!(value, field, max_length = nil)
      if !value.is_a?(String) || value.strip.empty? || value.match?(CONTROL) ||
         (max_length && value.length > max_length)
        raise ArgumentError, "Invalid Hub Network #{field}"
      end

      value
    end

    def port!(value, field = 'target port')
      raise ArgumentError, "Invalid Hub Network #{field}" unless value.is_a?(Integer) && value.between?(1, 65_535)
    end

    def validate_policy(value)
      raise ArgumentError, 'Invalid Hub Network policy' unless value.is_a?(Hash) && value['mode'].is_a?(String)

      case value['mode']
      when 'hub', 'private', 'disabled' then nil
      when 'group' then string!(value['group'], 'policy group')
      when 'keys'
        keys = value['keys']
        valid = keys.is_a?(Array) && !keys.empty? && keys.all? do |key|
          string!(key, 'policy key')
          true
        rescue ArgumentError
          false
        end
        raise ArgumentError, 'Invalid Hub Network policy keys' unless valid
      else raise ArgumentError, 'Invalid Hub Network policy mode'
      end
    end

    # A share: {'name', 'protocol' => tcp|udp, 'target' => {'host', 'port'}, 'policy'?}.
    def validate_share(value)
      raise ArgumentError, 'Invalid Hub Network share' unless value.is_a?(Hash)

      string!(value['name'], 'share name', MAX_SHARE_NAME_LENGTH)
      raise ArgumentError, 'Invalid Hub Network protocol' unless %w[tcp udp].include?(value['protocol'])

      target = value['target']
      raise ArgumentError, 'Invalid Hub Network target' unless target.is_a?(Hash)

      string!(target['host'], 'target host')
      port!(target['port'])
      validate_policy(value['policy']) unless value['policy'].nil?
    end

    def validate_publication(value, share, index)
      raise ArgumentError, "Invalid Hub publication at share index #{index}" unless value.is_a?(Hash)
      raise ArgumentError, "Invalid Hub publication version at share index #{index}" unless value['version'] == WIRE_VERSION

      resource = value['resourceId']
      unless resource.is_a?(String) && resource.start_with?('hnr1_') && resource != 'hnr1_'
        raise ArgumentError, "Invalid Hub publication resourceId at share index #{index}"
      end

      string!(value['authority'], "publication authority at share index #{index}")
      string!(value['providerId'], "publication providerId at share index #{index}")
      string!(value['overlayAddress'], "publication overlayAddress at share index #{index}")
      raise ArgumentError, "Hub publication protocol mismatch at share index #{index}" unless value['protocol'] == share['protocol']

      port!(value['port'], "publication port at share index #{index}")
      value
    end

    # Declared shares, their agent attestations and hub publications.
    class Publisher
      attr_accessor :agent_socket, :agent_timeout, :attestation_provider
      attr_reader :publications

      def initialize(agent_socket: AGENT_SOCKET, agent_timeout: 5, attestation_provider: nil)
        @agent_socket = agent_socket
        @agent_timeout = agent_timeout
        @attestation_provider = attestation_provider
        @shares = {}
        @publications_by_share = {}
        @mutex = Mutex.new
      end

      def declared_shares
        @mutex.synchronize { @shares.keys.sort.map { |name| @shares[name] } }
      end

      def shares?
        @mutex.synchronize { !@shares.empty? }
      end

      # Declare a share; the next connect publishes the whole set.
      def declare_share(share)
        Network.validate_share(share)
        @mutex.synchronize { @shares[share['name']] = share }
      end

      def publications
        @mutex.synchronize { @publications_by_share.values }
      end

      def publication(name)
        @mutex.synchronize { @publications_by_share[name] }
      end

      # Prove the service key to the local agent; returns its attestation.
      def request_attestation(share, service_key, sign)
        Network.validate_share(share)
        body = { 'serviceKey' => service_key, 'shareName' => share['name'],
                 'protocol' => share['protocol'], 'target' => share['target'] }
        challenge = agent('/challenge', body, 'challenge')
        nonce = challenge.is_a?(Hash) ? challenge['nonce'] : nil
        unless nonce.is_a?(String) && !nonce.empty?
          raise LocalAgentError.new('invalid-agent-response', 'Hub Network agent returned an invalid challenge')
        end

        attestation = agent('/attest', body.merge('signature' => sign.call(nonce).to_s), 'attestation')
        validate_attestation(attestation, share, service_key)
        attestation
      end

      def publish_share(share, service_key, sign, sender)
        Network.validate_share(share)
        previous = @mutex.synchronize { @shares[share['name']].tap { @shares[share['name']] = share } }
        begin
          synchronize(service_key, sign, sender)
        rescue StandardError
          @mutex.synchronize { previous ? @shares[share['name']] = previous : @shares.delete(share['name']) }
          raise
        end
      end

      def republish_all(service_key, sign, sender)
        synchronize(service_key, sign, sender)
      end

      def remove_share(name, service_key, sign, sender)
        Network.string!(name, 'share name', MAX_SHARE_NAME_LENGTH)
        removed = @mutex.synchronize { @shares.delete(name) }
        raise KeyError, "Share '#{name}' not found" unless removed

        begin
          synchronize(service_key, sign, sender)
        rescue StandardError
          @mutex.synchronize { @shares[name] = removed }
          raise
        end
      end

      private

      def synchronize(service_key, sign, sender)
        shares = declared_shares
        wire = shares.map do |share|
          attestation = @attestation_provider ? @attestation_provider.call(share, service_key, sign) : request_attestation(share, service_key, sign)
          validate_attestation(attestation, share, service_key)
          share.merge('version' => WIRE_VERSION, 'attestation' => attestation)
        end
        response = sender.send('network/shares/replace', { 'shares' => wire })
        unless response.is_a?(Hash) && response['shares'].is_a?(Array)
          raise ArgumentError, 'Hub returned an invalid shares/replace response'
        end

        publications = response['shares']
        if publications.length != shares.length
          raise ArgumentError, "Hub returned #{publications.length} publications for #{shares.length} shares"
        end

        # v1 publications carry no share name: the hub keeps request order.
        correlated = {}
        shares.each_with_index do |share, index|
          validated = Network.validate_publication(publications[index], share, index)
          if correlated.values.any? { |p| p['resourceId'] == validated['resourceId'] }
            raise ArgumentError, "Hub returned duplicate resourceId at share index #{index}"
          end

          correlated[share['name']] = validated
        end
        @mutex.synchronize { @publications_by_share = correlated }
        correlated.values
      end

      def validate_attestation(attestation, share, service_key)
        target = attestation.is_a?(Hash) ? attestation['target'] : nil
        unless attestation.is_a?(Hash) && attestation['version'] == WIRE_VERSION &&
               attestation['serviceKey'] == service_key && attestation['shareName'] == share['name'] &&
               attestation['protocol'] == share['protocol'] && target.is_a?(Hash) &&
               target['host'] == share['target']['host'] && target['port'] == share['target']['port']
          raise LocalAgentError.new('attestation-mismatch', 'Local-agent attestation does not match the share')
        end

        issued = time(attestation['issuedAt'])
        expires = time(attestation['expiresAt'])
        now = Time.now.to_f
        return unless issued.nil? || expires.nil? || expires <= issued || issued > now + 30 || expires <= now

        raise LocalAgentError.new('attestation-expired', 'Local-agent attestation is expired')
      end

      def time(value)
        value.is_a?(String) ? Time.iso8601(value).to_f : nil
      rescue ArgumentError
        nil
      end

      # POST JSON to the agent over its Unix socket and decode the reply.
      def agent(path, body, operation)
        status, payload = begin
          Timeout.timeout(@agent_timeout) { post(path, body) }
        rescue Timeout::Error
          raise LocalAgentError.new('agent-timeout', "Hub Network agent timed out after #{(@agent_timeout * 1000).to_i} ms")
        rescue SystemCallError, IOError
          raise LocalAgentError.new('agent-unavailable', "Hub Network agent is unavailable at #{@agent_socket}")
        end
        unless (200..299).cover?(status)
          detail = payload.strip
          raise LocalAgentError.new('agent-rejected',
                                    "Hub Network agent rejected #{operation} (#{status})#{detail.empty? ? '' : ": #{detail}"}",
                                    status)
        end
        begin
          JSON.parse(payload)
        rescue JSON::ParserError
          raise LocalAgentError.new('invalid-agent-response', 'Hub Network agent returned invalid JSON', status)
        end
      end

      def post(path, body)
        data = JSON.generate(body)
        socket = UNIXSocket.new(@agent_socket)
        begin
          socket.write("POST #{path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n" \
                       "Content-Length: #{data.bytesize}\r\nConnection: close\r\n\r\n#{data}")
          parse_response(socket.read)
        ensure
          socket.close
        end
      end

      def parse_response(raw)
        head, body = raw.split("\r\n\r\n", 2)
        lines = head.to_s.split("\r\n")
        match = lines.first.to_s.match(%r{\AHTTP/1\.[01] (\d{3})})
        raise LocalAgentError.new('invalid-agent-response', 'Hub Network agent returned an invalid HTTP response') unless match

        headers = lines.drop(1).map { |line| line.split(':', 2).map(&:strip) }.to_h { |k, v| [k.downcase, v] }
        body = body.to_s
        if headers['transfer-encoding'].to_s.downcase == 'chunked'
          decoded = +''
          until body.empty?
            size_line, rest = body.split("\r\n", 2)
            size = size_line.split(';').first.to_i(16)
            break if size.zero?

            decoded << rest.byteslice(0, size)
            body = rest.byteslice(size + 2..-1).to_s
          end
          body = decoded
        elsif headers['content-length']
          body = body.byteslice(0, headers['content-length'].to_i)
        end
        [match[1].to_i, body]
      end
    end
  end
end
