module SafeBro
  # What SafeBro blocks, flags and locks right now. Read only: change it in the initializer.
  class RulesController < ApplicationController
    def show
      @config = SafeBro.config
      @protected_hosts = @config.protected_urls.filter_map { |url| host_of(url) }
    end

    private
      # Only host and port: a URL can carry a password.
      def host_of(url)
        uri = URI.parse(url.to_s.include?("://") ? url.to_s : "tcp://#{url}")
        [ uri.host, uri.port ].compact.join(":").presence
      rescue URI::InvalidURIError
        "(unreadable URL)"
      end
  end
end
