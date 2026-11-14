module SafeBro
  # Entry point for a console (or runner) process: installs the protections once, then
  # identifies the person, asks why, and opens a session.
  class Supervisor
    def run_console
      install
      start
    end

    def run_runner
      start(source: "runner", reason: runner_reason, username: runner_username, interactive: false)
      SafeBro.recorder.record_command(runner_statements)
    end

    def install
      return if @installed

      # Loaded ahead of time: without this, the first command in a real console raised
      # "uninitialized constant ActiveRecord::QueryMethods::Relation" (console1984 hit the same).
      require "active_record/relation"
      SafeBro.shield.install
      SafeBro.lock_down! if SafeBro.config.freeze_internals
      @installed = true
    end

    def start(source: "console", reason: nil, username: nil, interactive: true)
      SafeBro.shield.lock(silent: true)
      Terminal.say(SafeBro.config.welcome_message, :yellow) if interactive
      username ||= current_username
      reason ||= session_reason(username)
      SafeBro.recorder.start_session(username: username, reason: reason, source: source)
      at_exit { stop }
    end

    def stop
      SafeBro.recorder.finish_session
    end

    def current_username
      SafeBro.config.username_resolver.call.to_s.strip.presence ||
        (SafeBro.config.ask_for_username_if_empty && Terminal.interactive? && Terminal.ask("Please, enter your name:")) ||
        raise(MissingUsername)
    end

    private
      # CONSOLE_REASON answers without a terminal; otherwise ask, and refuse to continue without one.
      def session_reason(username)
        env_reason = ENV["CONSOLE_REASON"].to_s.squish.first(255).presence
        return env_reason if env_reason
        raise MissingReason unless Terminal.interactive?

        Terminal.ask("#{username}, why are you using this console today?")
      end

      # Runners are usually automation: don't refuse, but record that nobody said who or why.
      def runner_reason
        ENV["CONSOLE_REASON"].to_s.squish.first(255).presence || "(no reason given)"
      end

      def runner_username
        SafeBro.config.username_resolver.call.to_s.strip.presence || "(unattributed)"
      end

      def runner_statements
        "rails runner #{ARGV.join(' ')}".strip
      end
  end
end
