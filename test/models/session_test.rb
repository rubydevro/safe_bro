require "test_helper"

class SessionTest < ActiveSupport::TestCase
  def make_session(username: "alice", started: Time.current, **attrs)
    SafeBro::Session.create!(username: username, reason: "r", started_at: started, **attrs)
  end

  test "needing_attention covers unlocks and flagged commands, not clean sessions" do
    clean = make_session
    clean.commands.create!(statements: "1")

    unlocked = make_session
    unlocked.sensitive_accesses.create!(justification: "j", resources: "all", started_at: Time.current)

    flagged = make_session
    flagged.commands.create!(statements: "x", status: :blocked)

    suspicious = make_session
    suspicious.commands.create!(statements: "y", status: :suspicious)

    assert_equal [ flagged, suspicious, unlocked ].map(&:id).sort, SafeBro::Session.needing_attention.pluck(:id).sort
  end

  test "an audit sets the review status and the latest audit wins" do
    session = make_session
    assert session.review_pending?

    session.audits.create!(auditor: "bob", status: :flagged, notes: "looked at SSNs")
    assert session.reload.review_flagged?

    session.audits.create!(auditor: "carol", status: :approved)
    assert session.reload.review_approved?
    assert_equal 2, session.audits.count
    assert_equal "carol", session.last_audit.auditor
  end

  test "flagging needs notes" do
    audit = make_session.audits.new(auditor: "bob", status: :flagged)
    assert_not audit.valid?
    assert audit.errors[:notes].any?
  end

  test "audit notes are encrypted at rest" do
    make_session.audits.create!(auditor: "bob", status: :flagged, notes: "very secret finding")
    raw = ActiveRecord::Base.connection.select_value("SELECT notes FROM safe_bro_audits")
    assert_not_includes raw, "secret finding"
  end

  test "flagging notifies" do
    events = []
    subscriber = ActiveSupport::Notifications.subscribe("session_flagged.safe_bro") { |*, payload| events << payload }
    make_session.audits.create!(auditor: "bob", status: :flagged, notes: "n")
    make_session.audits.create!(auditor: "bob", status: :approved)
    assert_equal 1, events.size
    assert_equal "bob", events.sole[:auditor]
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end

  test "purge removes old sessions and their data, keeping flagged and recent ones" do
    old = make_session(started: 100.days.ago)
    old.commands.create!(statements: "x")
    old.sensitive_accesses.create!(justification: "j", resources: "all", started_at: 100.days.ago)
    old.audits.create!(auditor: "bob", status: :approved)
    old_flagged = make_session(started: 100.days.ago)
    old_flagged.audits.create!(auditor: "bob", status: :flagged, notes: "n")
    recent = make_session(started: 1.day.ago)

    assert_equal 1, SafeBro::Session.purge!(older_than: 90.days)

    assert_not SafeBro::Session.exists?(old.id)
    assert_equal 0, SafeBro::Command.where(session_id: old.id).count
    assert_equal 0, SafeBro::SensitiveAccess.where(session_id: old.id).count
    assert_equal 0, SafeBro::Audit.where(session_id: old.id).count
    assert SafeBro::Session.exists?(old_flagged.id)
    assert SafeBro::Session.exists?(recent.id)
  end

  test "purge can include flagged sessions, and nil retention keeps everything" do
    old_flagged = make_session(started: 100.days.ago)
    old_flagged.audits.create!(auditor: "bob", status: :flagged, notes: "n")

    assert_equal 0, SafeBro::Session.purge!(older_than: nil)
    assert_equal 1, SafeBro::Session.purge!(older_than: 90.days, keep_flagged: false)
  end

  test "the purge job uses the configured retention" do
    make_session(started: 10.days.ago)
    with_config(retention: 5.days) { SafeBro::PurgeJob.perform_now }
    assert_equal 0, SafeBro::Session.count
  end
end
