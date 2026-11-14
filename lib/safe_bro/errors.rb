module SafeBro
  class Error < StandardError; end

  # Setup problems that stop a console from starting (fail closed).
  class MissingUsername < Error
    def initialize(msg = "SafeBro needs to know who you are. Set CONSOLE_USER (e.g. via SSH SetEnv), or enable config.ask_for_username_if_empty.")
      super
    end
  end

  class MissingReason < Error
    def initialize(msg = "SafeBro needs a reason for this session. Set CONSOLE_REASON when there is no terminal to ask on.")
      super
    end
  end

  class NotInteractive < Error
    def initialize(msg = "This needs an interactive terminal.")
      super
    end
  end

  # Raised when a console command is not allowed. The command is not executed.
  class ForbiddenCommand < Error; end

  # Raised when a command tries to change SafeBro's own audit trail.
  class TamperingAttempt < ForbiddenCommand; end

  # Raised when a command touches a protected resource while the console is locked.
  class ProtectedResource < ForbiddenCommand
    attr_reader :resource

    def initialize(resource, detail = nil)
      @resource = resource
      super([ "Access to #{resource} is protected.", detail, "Run unlock! to get access (you will be asked why)." ].compact.join(" "))
    end
  end

  # Not blocked, but recorded as suspicious.
  class SuspiciousCommand < Error; end
end
