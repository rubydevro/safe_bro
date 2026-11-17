require "test_helper"

# SafeBro copies the key moments of a session to BroHub's shared audit log.
class TrailTest < ActiveSupport::TestCase
  def trail
    BroHub::AuditEvent.where(source: "safe_bro").order(:id)
  end

  test "a session start is logged with who, why, where from, and the host" do
    SafeBro.recorder.start_session(username: "alice", reason: "fix invoice 12", client_ip: "203.0.113.9")
    session = SafeBro.recorder.session
    SafeBro.recorder.finish_session

    entry = trail.sole
    assert_equal "session_started", entry.event
    assert_equal [ "alice", "fix invoice 12", "203.0.113.9", Socket.gethostname ], [ entry.user_label, entry.reason, entry.ip, entry.context ]
    assert_equal [ "session ##{session.id}", session.id.to_s ], [ entry.target, entry.reference ]
    assert_equal "console", entry.details["via"]
  end

  test "an unlock is logged with its justification, never with what was done while unlocked" do
    with_session(username: "alice") do
      unlock :credentials, justification: "rotate the stripe key"
      SafeBro.recorder.record_command("Rails.application.credentials.stripe")
    end

    entry = trail.find_by(event: "sensitive_unlocked")
    assert_equal [ "alice", "rotate the stripe key" ], [ entry.user_label, entry.reason ]
    assert_equal [ "credentials" ], entry.details["resources"]
    assert_no_match(/credentials\.stripe/, trail.to_a.map(&:attributes).to_json)
  end

  test "a flagged command is logged with the reason, not the command" do
    with_session do
      command = SafeBro.recorder.record_command("User.delete_all")
      SafeBro.recorder.flag(command, :blocked, "destructive")
    end

    entry = trail.find_by(event: "command_flagged")
    assert_equal "destructive", entry.reason
    assert_equal "blocked", entry.details["status"]
    assert_no_match(/delete_all/, entry.attributes.to_json)
  end

  test "a verdict is logged under the auditor, without the notes" do
    session = SafeBro::Session.create!(username: "alice", reason: "x", started_at: Time.current)
    session.audits.create!(auditor: "bob", status: :flagged, notes: "looked up customer cards")

    entry = trail.find_by(event: "session_reviewed")
    assert_equal "bob", entry.user_label
    assert_equal "flagged", entry.details["status"]
    assert_equal "alice", entry.details["session_user"]
    assert_no_match(/customer cards/, entry.attributes.to_json)
  end

  test "a missing audit table doesn't stop a console from opening, and SafeBro's own record is still written" do
    original = BroHub::Audit.method(:record)
    BroHub::Audit.define_singleton_method(:record) { |**| raise ActiveRecord::StatementInvalid, "no such table: bro_hub_audit_events" }

    with_session(username: "carol") { }
    assert_equal "carol", SafeBro::Session.sole.username
  ensure
    BroHub::Audit.define_singleton_method(:record, original)
  end

  test "the console can't read or change the shared audit table" do
    with_session do
      assert_raises(SafeBro::TamperingAttempt) { typed "BroHub::AuditEvent.delete_all" }
      assert_raises(SafeBro::TamperingAttempt) { typed "BroHub::AuditEvent.count" }
    end
    assert trail.exists?(event: "session_started")
  end
end
