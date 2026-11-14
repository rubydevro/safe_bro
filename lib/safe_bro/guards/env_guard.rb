module SafeBro
  module Guards
    # ENV holds secrets in most deployments. Reading a protected variable by name raises; dumping
    # the whole thing returns it with the protected values filtered.
    module EnvGuard
      FILTERED = "[FILTERED]".freeze
      KEYED = %i[ [] fetch ].freeze
      MULTI = %i[ values_at fetch_values slice ].freeze
      DUMPS = %i[ to_h to_hash to_a each each_pair select filter reject values key ].freeze
      # Shown whenever the console prints a value, not only when typed directly.
      DISPLAY = %i[ inspect ].freeze

      def self.redacted
        ENV.to_h.to_h { |name, value| [ name, SafeBro.config.protected_env_name?(name) ? FILTERED : value ] }
      end

      def self.guard_name!(name, caller_locations)
        return unless SafeBro.config.protected_env_name?(name)

        SafeBro.guard!(:env, "(#{name})", locations: caller_locations)
      end

      module Guard
        EnvGuard::KEYED.each do |method_name|
          define_method(method_name) do |name, *args, **kwargs, &block|
            EnvGuard.guard_name!(name, caller_locations(1, 1)) if SafeBro.executor.executing_user_command?
            super(name, *args, **kwargs, &block)
          end
        end

        EnvGuard::MULTI.each do |method_name|
          define_method(method_name) do |*names, **kwargs, &block|
            if SafeBro.executor.executing_user_command?
              locations = caller_locations(1, 1)
              names.flatten.each { |name| EnvGuard.guard_name!(name, locations) }
            end
            super(*names, **kwargs, &block)
          end
        end

        EnvGuard::DUMPS.each do |method_name|
          define_method(method_name) do |*args, **kwargs, &block|
            if SafeBro.executor.executing_user_command? && SafeBro.executor.from_console?(caller_locations(1, 1)) && SafeBro.shield.protects?(:env)
              EnvGuard.redacted.public_send(method_name, *args, **kwargs, &block)
            else
              super(*args, **kwargs, &block)
            end
          end
        end

        EnvGuard::DISPLAY.each do |method_name|
          define_method(method_name) do |*args, **kwargs, &block|
            if SafeBro.executor.executing_user_command? && SafeBro.shield.protects?(:env)
              EnvGuard.redacted.public_send(method_name, *args, **kwargs, &block)
            else
              super(*args, **kwargs, &block)
            end
          end
        end
      end

      def self.install
        ENV.singleton_class.prepend(Guard)
      end
    end
  end
end
