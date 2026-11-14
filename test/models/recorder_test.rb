require "test_helper"

class RecorderTest < ActiveSupport::TestCase
  test "records who, why and where" do
    with_session(username: "alice", reason: "fix invoice 12") do |session|
      assert_equal "alice", session.username
      assert_equal "fix invoice 12", session.reason
      assert_equal "console", session.source
      assert_equal Process.pid, session.pid
      assert_equal Socket.gethostname, session.hostname
      assert session.open?
    end
    assert_not SafeBro::Session.last.open?
  end

  test "finishing closes an open unlock window" do
    with_session do |session|
      unlock
    end
    assert_not_nil SafeBro::SensitiveAccess.last.ended_at
  end

  test "flags are recorded and notified" do
    events = []
    subscriber = ActiveSupport::Notifications.subscribe("command_flagged.safe_bro") { |*, payload| events << payload }
    with_session do |session|
      command = SafeBro.recorder.record_command("foo")
      SafeBro.recorder.flag(command, :blocked, "because")
      assert_equal "because", command.reload.flag_reason
      assert command.blocked?
    end
    assert_equal "because", events.sole[:reason]
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end

  test "a failing notification subscriber doesn't break recording" do
    subscriber = ActiveSupport::Notifications.subscribe("session_started.safe_bro") { raise "mail is down" }
    assert_nothing_raised { with_session { } }
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end
end
