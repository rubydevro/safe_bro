module SafeBro
  # Supervises every command typed into the console:
  #
  # * records it (before it runs, so a crash can't hide it)
  # * validates it, blocking forbidden commands and flagging suspicious ones
  # * runs it with the shield's protections on
  # * flags attempts to reach protected resources that happen while it runs
  class Executor
    # console_path: the file name IRB gives the code it evaluates, e.g. "(irb)" or "(myapp)" (Rails
    # names it after the app). It is how we tell typed code from library code.
    def execute(commands, console_path: nil, &block)
      @console_path = console_path if console_path
      statements = Array(commands)
      command = run_as_system { SafeBro.recorder.record_command(statements) }

      if (suspicion = validate(command, statements))
        flag(command, :suspicious, suspicion.message)
      end

      begin
        execute_in_protected_mode(&block)
      rescue ProtectedResource, ForbiddenCommand => error
        flag(command, error.is_a?(ProtectedResource) ? :suspicious : :blocked, error.message)
        raise masked(error)
      rescue FrozenError => error
        # Someone tried to alter a frozen SafeBro class.
        flag(command, :blocked, "Attempt to modify protected code: #{error.message}")
        raise masked(error)
      rescue => error
        raise masked(error)
      end
    end

    # Runs the block with the shield's protections on. The mode itself decides what is
    # protected, depending on what is currently unlocked.
    def execute_in_protected_mode(&block)
      run_as_user { SafeBro.shield.protect(&block) }
    end

    def run_as_user(&block)
      run_command(true, &block)
    end

    def run_as_system(&block)
      run_command(false, &block)
    end

    def executing_user_command?
      @executing_user_command == true
    end

    # Was this method called straight from what the person typed (as opposed to from library code)?
    # IRB evaluates input under a fixed file name, and C-implemented methods like send or
    # instance_eval don't add frames, so the caller location is still the console.
    def from_console?(locations)
      executing_user_command? && locations.first&.path.to_s == (@console_path || "(irb)")
    end

    private
      # Returns a suspicion (command still runs) or raises ForbiddenCommand (it doesn't).
      def validate(command, statements)
        run_as_system { SafeBro.validator.validate(statements, locked: SafeBro.shield.locked?) }
        nil
      rescue SuspiciousCommand => suspicion
        suspicion
      rescue ForbiddenCommand => error
        flag(command, :blocked, error.message)
        raise masked(error)
      end

      def flag(command, status, reason)
        run_as_system { SafeBro.recorder.flag(command, status, reason) }
        Terminal.alert "#{status == :blocked ? 'blocked' : 'flagged for review'} - #{reason}"
      end

      def run_command(by_user)
        original = @executing_user_command
        @executing_user_command = by_user
        yield
      ensure
        @executing_user_command = original
      end

      # Error messages are built lazily and IRB prints them after the command finished, i.e.
      # outside the shield. Build them inside it, so they can't leak what the command couldn't read.
      def masked(error)
        %i[ message to_s inspect detailed_message ].each do |name|
          next unless error.respond_to?(name)

          original = error.method(name)
          error.define_singleton_method(name) do |*args, **kwargs|
            SafeBro.executor.execute_in_protected_mode { original.call(*args, **kwargs) }
          end
        end
        error
      rescue FrozenError
        error
      end
  end
end
