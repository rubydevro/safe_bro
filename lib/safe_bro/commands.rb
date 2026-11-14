module SafeBro
  # The commands people can type into the console: `unlock!` and `lock!`.
  module Commands
    class Unlock < IRB::Command::Base
      category "SafeBro"
      description "Get access to protected data (asks why, and records it). Optionally name what: unlock! :credentials"

      def execute(arg)
        resources = arg.to_s.scan(/\w+/).map(&:to_sym)
        SafeBro.shield.unlock(resources.presence || [ :all ])
        nil
      end
    end

    class Lock < IRB::Command::Base
      category "SafeBro"
      description "Protect sensitive data again."

      def execute(_arg)
        SafeBro.shield.lock
        nil
      end
    end
  end
end
