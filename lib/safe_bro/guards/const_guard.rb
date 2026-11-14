module SafeBro
  module Guards
    # Constants can be built from strings (Object.const_get("Safe" + "Bro"), "SafeBro".constantize),
    # which the validator can't see. Resolve them through the validator when asked from the console.
    module ConstGuard
      module Lookup
        def const_get(name, *args)
          ConstGuard.check!(name, caller_locations(1, 1)) if SafeBro.executor.executing_user_command?
          super
        end
      end

      module StringLookup
        def constantize
          ConstGuard.check!(self, caller_locations(1, 1)) if SafeBro.executor.executing_user_command?
          super
        end

        def safe_constantize
          ConstGuard.check!(self, caller_locations(1, 1)) if SafeBro.executor.executing_user_command?
          super
        end
      end

      def self.check!(name, locations)
        return unless SafeBro.executor.from_console?(locations)

        SafeBro.executor.run_as_system { SafeBro.validator.validate(name.to_s, locked: SafeBro.shield.locked?) }
      rescue SuspiciousCommand
        nil
      end

      def self.install
        Module.prepend(Lookup)
        String.prepend(StringLookup)
      end
    end
  end
end
