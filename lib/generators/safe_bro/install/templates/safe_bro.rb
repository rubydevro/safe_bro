SafeBro.configure do |config|
  # --- Who may review console sessions in the SafeBro UI --------------------------------
  # Nobody until you say so. The review UI is a section of the BroHub dashboard, so who is
  # signed in comes from BroHub.config.current_user (your ApplicationController's `current_user`
  # by default). Override it for SafeBro only with config.current_user below.
  config.can_audit = ->(user) { false }
  # config.current_user = ->(controller) { controller.current_user }
  # config.user_label = ->(user) { user.email }
  # config.allow_self_audit = false

  # --- Where SafeBro acts ----------------------------------------------------------------
  # Consoles started in these environments are recorded and guarded.
  # config.protected_environments = %w[ production ]

  # How SafeBro learns who is at the console. Set it where you can trust it: with SSH,
  # `environment="CONSOLE_USER=jane"` on the key in authorized_keys. A SetEnv from the
  # client can be set to anything.
  # config.username_resolver = -> { ENV["CONSOLE_USER"] }
  # config.ask_for_username_if_empty = false

  # Where the person connected from, stored with the session. Default: CONSOLE_CLIENT_IP, then SSH_CLIENT.
  # Inside a container pass it in, e.g. `docker run -e CONSOLE_CLIENT_IP="${SSH_CLIENT%% *}" ...`.
  # config.client_ip_resolver = -> { ENV["CONSOLE_CLIENT_IP"] }

  # --- What is protected until someone runs unlock! ---------------------------------------
  # config.protected_resources = %i[ encrypted_data credentials env files network ]
  # config.protected_urls = [ "redis://cache.internal:6379", "https://search.internal:9200" ]
  # config.protected_env_patterns += [ /STRIPE/ ]
  # config.protected_file_patterns += [ %r{config/.*\.pem\z} ]

  # --- Guardrails -------------------------------------------------------------------------
  # config.forbidden_methods += [ "Kernel#open" ]
  # config.suspicious_terms += [ "DROP TABLE" ]

  # --- Retention ---------------------------------------------------------------------------
  # Sessions older than this are removed by SafeBro::PurgeJob (schedule it) or
  # `bin/rails safe_bro:purge`. Flagged sessions are kept. nil keeps everything.
  # config.retention = 90.days
  # config.keep_flagged = true

  # Also record `rails runner` invocations as sessions.
  # config.audit_runner = false
end

# Get told when something needs attention:
#
# ActiveSupport::Notifications.subscribe("command_flagged.safe_bro") do |*, payload|
#   SecurityMailer.console_flag(payload[:session], payload[:reason]).deliver_later
# end
