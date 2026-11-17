require "irb"
require "reline"
require "set"
require "socket"

require "bro_hub"
require "safe_bro/version"
require "safe_bro/errors"
require "safe_bro/configuration"
require "safe_bro/cipher"
require "safe_bro/parsed_command"
require "safe_bro/validator"
require "safe_bro/terminal"
require "safe_bro/trail"
require "safe_bro/recorder"
require "safe_bro/executor"
require "safe_bro/guards/guarded"
require "safe_bro/guards/sql_guard"
require "safe_bro/guards/network_guard"
require "safe_bro/guards/credentials_guard"
require "safe_bro/guards/env_guard"
require "safe_bro/guards/file_guard"
require "safe_bro/guards/method_guard"
require "safe_bro/guards/const_guard"
require "safe_bro/guards/irb_context"
require "safe_bro/commands"
require "safe_bro/shield"
require "safe_bro/supervisor"
require "safe_bro/engine"

# = SafeBro
#
# Audited, guarded Rails console access.
#
# * Every console session is recorded: who, why, and every command (encrypted at rest).
# * Sensitive data (encrypted attributes, credentials, ENV secrets, protected systems) is
#   locked until the person runs unlock! and explains why. Everything done while unlocked
#   is linked to that justification.
# * Commands are checked before they run: forbidden ones are blocked, suspicious ones flagged.
# * The audit trail itself can't be changed from the console.
# * Auditors review sessions in a mountable engine.
#
# Access from the console is a deterrent plus an audit trail, not a sandbox. See the README.
module SafeBro
  class << self
    attr_accessor :debug

    def config
      @config ||= Configuration.new
    end

    def configure
      yield config
    end

    def reset_config!
      @config = nil
    end

    def enabled?
      config.enabled?
    end

    # The collaborators are created on first use and then shared.
    def supervisor = @supervisor ||= Supervisor.new
    def shield = @shield ||= Shield.new
    def executor = @executor ||= Executor.new
    def recorder = @recorder ||= Recorder.new
    def validator = @validator ||= Validator.new(config)

    # For gems that expose sensitive things (e.g. a credentials reveal): call this first.
    # Raises ProtectedResource when running under a console command while the resource is
    # locked. With `locations:` (caller_locations) it only raises for calls made directly
    # from what the person typed.
    def guard!(resource, detail = nil, locations: nil)
      return unless executor.executing_user_command? && shield.protects?(resource)
      return if locations && !executor.from_console?(locations)

      raise ProtectedResource.new(resource, detail)
    end

    # Subscribe with ActiveSupport::Notifications.subscribe(/\.safe_bro\z/) to alert people.
    # Events: session_started, unlocked, command_flagged, session_flagged.
    def notify(event, **payload)
      ActiveSupport::Notifications.instrument("#{event}.safe_bro", payload)
    rescue => error
      Rails.logger&.error("SafeBro: notification #{event} failed: #{error.class}: #{error.message}")
    end

    # Freezes configuration and SafeBro's own classes so they can't be monkey patched from a console.
    def lock_down!
      config.lock_down!
      [ Executor, Shield, Recorder, Supervisor, Validator, Validator::Validation, *Validator::VALIDATIONS,
        ParsedCommand, Terminal, Commands::Unlock, Commands::Lock, Guards::Guarded, Guards::SqlGuard,
        Guards::EnvGuard, Guards::FileGuard, Guards::MethodGuard, Guards::ConstGuard, Guards::CredentialsGuard, Guards::CredentialsGuard::Inspect,
        Guards::IrbContext ].each(&:freeze)
    end
  end
end
