module SafeBro
  class ApplicationController < SafeBro.config.parent_controller.constantize
    include BroHub::Layout
    bro_hub_section :safe_bro

    protect_from_forgery with: :exception

    before_action :safe_bro_require_ssl
    before_action :safe_bro_no_store
    before_action :safe_bro_authorize!

    helper_method :safe_bro_user, :safe_bro_user_label

    rescue_from SafeBro::Error, with: :safe_bro_forbidden

    private
      # The shell shows who is signed in, by SafeBro's rules.
      def bro_hub_user
        safe_bro_user
      end

      def safe_bro_user
        return @safe_bro_user if defined?(@safe_bro_user)

        @safe_bro_user = SafeBro.config.current_user.call(self)
      end

      def safe_bro_user_label
        SafeBro.config.user_label.call(safe_bro_user) if safe_bro_user
      end

      def safe_bro_authorize!
        raise SafeBro::Error, "Not allowed" unless safe_bro_user && SafeBro.config.can_audit.call(safe_bro_user)
      end

      def safe_bro_require_ssl
        head :forbidden if SafeBro.config.require_ssl && !request.ssl?
      end

      # Sessions contain what people typed in production: keep it out of caches.
      def safe_bro_no_store
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
      end

      def safe_bro_forbidden
        render "safe_bro/shared/forbidden", status: :forbidden
      end
  end
end
