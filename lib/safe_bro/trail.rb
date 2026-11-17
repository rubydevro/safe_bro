module SafeBro
  # The key moments of a session, copied to BroHub's shared audit log so they show up next to what the other
  # Bro gems record: a session starting, the console being unlocked, a command being flagged, a verdict.
  #
  # SafeBro's own tables stay the full record (every command, every unlock window). This is the short version,
  # and it never holds a command, its output or an auditor's notes. It is best effort: SafeBro's own tables are
  # written first, so a missing audit table (BroHub's migration not run yet) must not stop a console from opening.
  module Trail
    SOURCE = "safe_bro".freeze

    module_function

    def record(event, session:, user: session.username, reason: nil, **details)
      BroHub::Audit.record(
        source: SOURCE, event: event, user: user.to_s,
        context: session.hostname, target: "session ##{session.id}", reference: session.id.to_s,
        reason: reason, ip: session.client_ip, **details
      )
    rescue StandardError => error
      Rails.logger&.error("SafeBro: could not copy #{event} to the BroHub audit log (#{error.class}: #{error.message})")
      nil
    end
  end
end
