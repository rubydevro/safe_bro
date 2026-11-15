module SafeBro
  # Writes the audit trail. Everything here runs as the system (never as a user command),
  # and silences SQL logging so the trail doesn't spill into the console.
  class Recorder
    attr_reader :session, :sensitive_access

    def start_session(username:, reason:, source: "console", client_ip: nil)
      quietly do
        @session = Session.create!(
          username: username, reason: reason, source: source, client_ip: client_ip,
          hostname: Socket.gethostname, pid: Process.pid, started_at: Time.current
        )
      end
      SafeBro.notify(:session_started, session: @session)
      @session
    end

    def finish_session
      return unless @session

      quietly do
        end_sensitive_access
        @session.update!(ended_at: Time.current)
      end
      @session = nil
    end

    # resources: array of symbols, e.g. [:all] or [:credentials]
    def start_sensitive_access(resources, justification)
      quietly do
        end_sensitive_access
        @sensitive_access = session.sensitive_accesses.create!(
          resources: resources.join(","), justification: justification, started_at: Time.current
        )
      end
      SafeBro.notify(:unlocked, session: session, access: @sensitive_access)
      @sensitive_access
    end

    def end_sensitive_access
      return unless @sensitive_access

      quietly { @sensitive_access.update!(ended_at: Time.current) }
      @sensitive_access = nil
    end

    # Records a command before it runs, linked to the current unlock window if any.
    def record_command(statements)
      quietly do
        session.commands.create!(statements: Array(statements).join("\n").strip, sensitive_access: sensitive_access)
      end
    end

    def flag(command, status, reason)
      quietly { command.update!(status: status, flag_reason: reason) }
      SafeBro.notify(:command_flagged, session: session, command: command, status: status, reason: reason)
      command
    end

    private
      def quietly(&block)
        SafeBro.executor.run_as_system do
          if SafeBro.debug
            ensure_connected(&block)
          else
            ActiveRecord::Base.logger.silence { ensure_connected(&block) }
          end
        end
      end

      def ensure_connected
        connection = Session.connection
        connection.reconnect! unless connection.active?
        yield
      end
  end
end
