module SafeBro
  class Configuration
    # --- Where it runs -------------------------------------------------------------------

    # SafeBro only acts on consoles started in these environments. Override with `enabled`.
    attr_accessor :protected_environments

    # true/false to force it on or off regardless of the environment.
    attr_accessor :enabled

    # Also record `rails runner` invocations as sessions.
    attr_accessor :audit_runner

    # --- Who is using the console --------------------------------------------------------

    # -> { "name" } The identity of the person at the console. Trust this only as much as the
    # layer that sets it (e.g. SSH `environment=` in authorized_keys is trustworthy, `SetEnv`
    # from the client is not).
    attr_accessor :username_resolver

    # Ask on the terminal when the resolver returns nothing (otherwise the console refuses to start).
    attr_accessor :ask_for_username_if_empty

    # -> { "203.0.113.7" } Where the person connected from, stored with each session. The default reads
    # CONSOLE_CLIENT_IP (set it where you trust it, e.g. your console wrapper from $SSH_CLIENT), then
    # SSH_CLIENT / SSH_CONNECTION. Values that aren't an IP address are ignored.
    attr_accessor :client_ip_resolver

    # --- What is protected ---------------------------------------------------------------

    # Which resources need unlock! (see Shield::RESOURCES).
    attr_accessor :protected_resources

    # URLs (https://host:port, redis://host:port, host:port) that can't be reached while locked.
    attr_accessor :protected_urls

    # ENV names that can't be read while locked (matched against the variable name).
    attr_accessor :protected_env_patterns

    # Files that can't be read from the console while locked.
    attr_accessor :protected_file_patterns

    # --- Guardrails ----------------------------------------------------------------------

    # Classes/modules the console may not reopen (class Foo / module Foo / Foo.class_eval...).
    attr_accessor :forbidden_reopening

    # Constants the console may not reference. :always, or only while :locked.
    attr_accessor :forbidden_constants

    # "Owner#instance_method" or "Owner.singleton_method" that can't be called from the console.
    attr_accessor :forbidden_methods

    # Commands containing one of these are allowed but recorded as suspicious.
    attr_accessor :suspicious_terms

    # Freeze SafeBro's own classes once installed so they can't be monkey patched.
    attr_accessor :freeze_internals

    # --- Storage and review --------------------------------------------------------------

    # Keep sessions this long, nil to keep forever (see SafeBro::PurgeJob / safe_bro:purge).
    attr_accessor :retention

    # Don't purge sessions an auditor flagged.
    attr_accessor :keep_flagged

    # 32 bytes (or a ->{ } returning them) used to encrypt recorded commands. Defaults to a key
    # derived from the app's secret_key_base.
    attr_accessor :encryption_key

    # Controller the engine controllers inherit from (gives access to your authentication).
    attr_accessor :parent_controller

    # ->(controller) { user or nil }. Defaults to BroHub.config.current_user, so configuring BroHub once is enough.
    attr_accessor :current_user

    # ->(user) { "label" } shown in the UI and stored on audits. Defaults to BroHub.config.user_label.
    attr_accessor :user_label

    # ->(user) { true/false } may this user review sessions in the UI?
    attr_accessor :can_audit

    # May an auditor approve their own sessions? (compared by user_label vs session username)
    attr_accessor :allow_self_audit

    attr_accessor :require_ssl

    # Texts shown in the console.
    attr_accessor :welcome_message, :unlock_prompt, :unlocked_message, :locked_message

    def initialize
      @protected_environments = %w[ production ]
      @enabled = nil
      @audit_runner = false

      @username_resolver = -> { ENV["CONSOLE_USER"] }
      @ask_for_username_if_empty = false
      @client_ip_resolver = -> { ENV["CONSOLE_CLIENT_IP"].presence || ENV["SSH_CLIENT"].to_s.split.first || ENV["SSH_CONNECTION"].to_s.split.first }

      @protected_resources = %i[ encrypted_data credentials env files network ]
      @protected_urls = []
      @protected_env_patterns = [ /SECRET/i, /TOKEN/i, /PASSWORD/i, /PASSPHRASE/i, /CREDENTIAL/i, /API_?KEY/i, /PRIVATE/i, /MASTER_?KEY/i, /DATABASE_URL/i, /\A[A-Z_]*KEY\z/ ]
      @protected_file_patterns = [ %r{config/master\.key\z}, %r{config/credentials/.+\.key\z}, %r{(\A|/)\.env(\.[^/]+)?\z} ]

      @forbidden_reopening = %w[ ActiveRecord ApplicationRecord SafeBro IRB ]
      @forbidden_constants = {
        always: %w[ SafeBro IRB ObjectSpace ],
        locked: %w[ ActiveRecord::Encryption Open3 PTY Fiddle ]
      }
      @forbidden_methods = %w[
        Kernel#eval Kernel.eval BasicObject#instance_eval BasicObject#instance_exec
        Module#class_eval Module#module_eval Module#class_exec Module#module_exec
        Kernel#system Kernel#exec Kernel#spawn Kernel#` Kernel#fork
        Kernel.system Kernel.exec Kernel.spawn Kernel.` Kernel.fork
        Process.spawn Process.exec Process.fork IO.popen
      ]
      @suspicious_terms = %w[ secret credentials master.key ENV safe_bro SafeBro ]
      @freeze_internals = true

      @retention = 90.days
      @keep_flagged = true
      @encryption_key = nil

      @parent_controller = "::ApplicationController"
      @current_user = ->(controller) { BroHub.config.current_user.call(controller) }
      @user_label = ->(user) { BroHub.config.user_label.call(user) }
      @can_audit = ->(_user) { false }
      @allow_self_audit = false
      @require_ssl = defined?(Rails) && Rails.env.production?

      @welcome_message = "You have access to production data here. That's a big deal. Everything you type is recorded and " \
                         "reviewed. Be careful, be brief, and don't look at data you don't need."
      @unlock_prompt = "Before you access sensitive data (encrypted attributes, credentials, ENV, protected systems), " \
                       "say why and where we can find the consent or ticket that covers it."
      @unlocked_message = "Unlocked. We pay extra close attention to everything you do now. Type lock! to protect it again."
      @locked_message = "Locked again. When we review, we may reach out about what you did while unlocked."
    end

    def enabled?
      return enabled unless enabled.nil?

      protected_environments.map(&:to_s).include?(Rails.env.to_s)
    end

    def protected_env_name?(name)
      protected_env_patterns.any? { |pattern| pattern.match?(name.to_s) }
    end

    # Freezes everything so it can't be altered from a console.
    def lock_down!
      [ protected_environments, protected_resources, protected_urls, protected_env_patterns, protected_file_patterns,
        forbidden_reopening, forbidden_methods, suspicious_terms ].each(&:freeze)
      forbidden_constants.each_value(&:freeze)
      forbidden_constants.freeze
      freeze
    end
  end
end
