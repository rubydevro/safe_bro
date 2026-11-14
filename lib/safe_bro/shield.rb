module SafeBro
  # The shield decides what is protected right now. Everything starts locked. unlock! asks for
  # a justification, records it, and opens the requested resources until lock!.
  #
  # Resources:
  #   encrypted_data - Active Record encrypted attributes read as ciphertext
  #   credentials    - Rails credentials, their keys, secret_key_base
  #   env            - ENV values whose names look secret
  #   files          - master.key, .env files
  #   network        - connections to config.protected_urls
  class Shield
    RESOURCES = %i[ encrypted_data credentials env files network ].freeze

    def initialize
      @unlocked = Set.new
    end

    def locked?
      @unlocked.empty?
    end

    def unlocked?(resource)
      @unlocked.include?(:all) || @unlocked.include?(resource)
    end

    # Is this resource protected from the console right now?
    def protects?(resource)
      SafeBro.config.protected_resources.include?(resource) && !unlocked?(resource)
    end

    def unlock(resources = [ :all ])
      unknown = resources - RESOURCES - SafeBro.config.protected_resources - [ :all ]
      raise ArgumentError, "Unknown resource #{unknown.first.inspect}. Choose from #{(RESOURCES | SafeBro.config.protected_resources).join(', ')}." if unknown.any?

      SafeBro.executor.run_as_system do
        justification = Terminal.ask(SafeBro.config.unlock_prompt)
        SafeBro.recorder.start_sensitive_access(resources, justification)
        @unlocked = Set.new(resources)
        Terminal.say(SafeBro.config.unlocked_message, :yellow)
      end
    end

    def lock(silent: false)
      SafeBro.executor.run_as_system do
        was_unlocked = !locked?
        SafeBro.recorder.end_sensitive_access if SafeBro.recorder.session
        @unlocked = Set.new
        Terminal.say(SafeBro.config.locked_message, :yellow) if was_unlocked && !silent
      end
    end

    # Runs the block with the protections that work by wrapping execution switched on.
    def protect(&block)
      if protects?(:encrypted_data) && encryption_available?
        ActiveRecord::Encryption.protecting_encrypted_data(&block)
      else
        block.call
      end
    end

    def install
      ActiveRecord::ConnectionAdapters::AbstractAdapter.prepend(Guards::SqlGuard)
      Guards::NetworkGuard.install if SafeBro.config.protected_urls.any?
      Guards::CredentialsGuard.install
      Guards::EnvGuard.install
      Guards::FileGuard.install
      Guards::ConstGuard.install
      Guards::MethodGuard.install
      install_irb
    end

    private
      def install_irb
        IRB::Context.prepend(Guards::IrbContext)
        IRB::Command.register(:unlock!, Commands::Unlock)
        IRB::Command.register(:lock!, Commands::Lock)
      end

      def encryption_available?
        defined?(ActiveRecord::Encryption) && ActiveRecord::Encryption.respond_to?(:protecting_encrypted_data)
      end
  end
end
