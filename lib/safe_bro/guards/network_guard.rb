require "socket"
require "uri"

module SafeBro
  module Guards
    # Stops connections to protected systems (Redis, Elasticsearch, ...) while the network
    # resource is locked. It checks new connections and writes on existing ones, so a
    # connection pool opened before the command started doesn't get a free pass.
    module NetworkGuard
      class << self
        def check!(host:, port:)
          return unless SafeBro.executor.executing_user_command? && SafeBro.shield.protects?(:network)
          return unless protected?(host, port)

          raise ProtectedResource.new(:network, "(#{host}:#{port})")
        end

        # Existing connection: look at who it is connected to.
        def check_socket!(socket)
          address = socket.respond_to?(:remote_address) ? socket.remote_address : socket.to_io.remote_address
          check!(host: address.ip_address, port: address.ip_port) if address.ip?
        rescue SocketError, Errno::ENOTCONN, IOError
          nil # not connected (yet): nothing to protect
        end

        def protected?(host, port)
          targets.any? do |target|
            target[:port] == port.to_i && (target[:host] == host.to_s || target[:addresses].include?(host.to_s))
          end
        end

        def reset!
          @targets = nil
        end

        private
          def targets
            @targets ||= SafeBro.config.protected_urls.map do |url|
              host, port = host_and_port(url)
              { host: host, port: port.to_i, addresses: resolve(host, port) }
            end
          end

          def resolve(host, port)
            Addrinfo.getaddrinfo(host, port, nil, :STREAM).map(&:ip_address)
          rescue SocketError
            []
          end

          def host_and_port(url)
            uri = URI.parse(url.to_s)
            return [ uri.host, uri.port ] if uri.host

            host, _, port = url.to_s.rpartition(":")
            [ host, port ]
          rescue URI::InvalidURIError
            host, _, port = url.to_s.rpartition(":")
            [ host, port ]
          end
      end

      module Connect
        def initialize(host, port, *args, **kwargs)
          NetworkGuard.check!(host: host, port: port)
          super
        end
      end

      module Writes
        %i[ write write_nonblock syswrite ].each do |name|
          define_method(name) do |*args, **kwargs, &block|
            NetworkGuard.check_socket!(self) if SafeBro.executor.executing_user_command?
            super(*args, **kwargs, &block)
          end
        end
      end

      module SocketConnect
        %i[ connect connect_nonblock ].each do |name|
          define_method(name) do |remote, *args, **kwargs|
            if SafeBro.executor.executing_user_command?
              address = remote.is_a?(Addrinfo) ? remote : Addrinfo.new(remote)
              NetworkGuard.check!(host: address.ip_address, port: address.ip_port) if address.ip?
            end
            super(remote, *args, **kwargs)
          end
        end
      end

      def self.install
        TCPSocket.prepend(Connect)
        BasicSocket.prepend(Writes)
        Socket.prepend(SocketConnect)
        OpenSSL::SSL::SSLSocket.prepend(Writes) if defined?(OpenSSL::SSL::SSLSocket)
      end
    end
  end
end
