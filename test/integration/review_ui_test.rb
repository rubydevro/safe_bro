require "test_helper"

class ReviewUiTest < ActionDispatch::IntegrationTest
  def sign_in_as(role)
    post "/role", params: { role: role }
  end

  def make_session(username: "alice", reason: "fix invoice", started: Time.current)
    SafeBro::Session.create!(username: username, reason: reason, started_at: started)
  end

  test "nobody gets in without being an auditor" do
    get "/console"
    assert_response :forbidden

    sign_in_as "staff"
    get "/console"
    assert_response :forbidden
    assert_select ".bh-title", /Not allowed/

    sign_in_as "auditor"
    get "/console"
    assert_response :success
  end

  test "the list shows pending sessions by default, with flags" do
    pending = make_session(reason: "pending one")
    approved = make_session(reason: "approved one")
    approved.audits.create!(auditor: "bob", status: :approved)
    pending.commands.create!(statements: "x", status: :blocked)
    pending.sensitive_accesses.create!(justification: "j", resources: "all", started_at: Time.current)

    sign_in_as "auditor"
    get "/console"
    assert_select ".bh-row", /pending one/
    assert_select ".bh-row", text: /approved one/, count: 0
    assert_select ".bh-tag.is-red", /1 flagged/
    assert_select ".bh-tag.is-amber", /1 unlock/
    assert_select ".bh-title", /1\s+awaiting a verdict/
  end

  test "filters by status, user, date and attention" do
    flagged = make_session(username: "carol", reason: "carol flagged")
    flagged.audits.create!(auditor: "bob", status: :flagged, notes: "n")
    old = make_session(username: "dave", reason: "dave old", started: Date.new(2026, 1, 5).to_time)
    sensitive = make_session(username: "erin", reason: "erin unlocked")
    sensitive.sensitive_accesses.create!(justification: "j", resources: "all", started_at: Time.current)

    sign_in_as "auditor"

    get "/console", params: { status: "flagged" }
    assert_select ".bh-row", /carol flagged/
    assert_select ".bh-row", text: /erin/, count: 0

    get "/console", params: { status: "all", username: "dave" }
    assert_select ".bh-row", /dave old/
    assert_select ".bh-row", text: /carol/, count: 0

    get "/console", params: { status: "all", from: "2026-01-01", to: "2026-01-31" }
    assert_select ".bh-row", /dave old/
    assert_select ".bh-row", text: /erin/, count: 0

    get "/console", params: { status: "all", attention: "1" }
    assert_select ".bh-row", /erin unlocked/
    assert_select ".bh-row", text: /dave/, count: 0

    get "/console", params: { status: "all", from: "not a date" }
    assert_response :success
  end

  test "the session page shows commands, flags and the unlock justification" do
    session = make_session
    session.commands.create!(statements: "Invoice.find(12).update(paid: true)")
    access = session.sensitive_accesses.create!(justification: "Ticket 77 says so", resources: "credentials", started_at: Time.current)
    session.commands.create!(statements: "Rails.application.credentials.stripe", status: :suspicious, flag_reason: "Command mentions credentials.", sensitive_access: access)
    session.commands.create!(statements: "eval('boom')", status: :blocked, flag_reason: "Calling eval is not allowed.")

    sign_in_as "auditor"
    get "/console/sessions/#{session.id}"
    assert_response :success
    assert_select "pre", "Invoice.find(12).update(paid: true)"
    assert_select ".bh-unlock", /Ticket 77 says so/
    assert_select ".bh-cmd.is-flagged.is-suspicious .bh-flag", "Flagged"
    assert_select ".bh-cmd.is-flagged.is-blocked .bh-flag", "Blocked"
    assert_select ".bh-cmd.is-sensitive", 1
    assert_select "form[action=?]", "/console/sessions/#{session.id}/audits"
  end

  test "approving records the audit and moves on to the next pending session" do
    first = make_session(reason: "first", started: 2.hours.ago)
    second = make_session(reason: "second", started: 1.hour.ago)

    sign_in_as "auditor"
    post "/console/sessions/#{second.id}/audits", params: { audit: { status: "approved", notes: "fine" }, filter_status: "pending" }

    assert_redirected_to "/console/sessions/#{first.id}?status=pending"
    assert second.reload.review_approved?
    audit = second.audits.sole
    assert_equal "auditor@example.com", audit.auditor
    assert_equal "fine", audit.notes

    post "/console/sessions/#{first.id}/audits", params: { audit: { status: "approved" }, filter_status: "pending" }
    assert_redirected_to "/console/?status=pending"
  end

  test "flagging without notes is refused" do
    session = make_session
    sign_in_as "auditor"
    post "/console/sessions/#{session.id}/audits", params: { audit: { status: "flagged", notes: "" } }
    assert_redirected_to %r{/console/sessions/#{session.id}}
    assert_empty session.audits
    follow_redirect!
    assert_select ".bh-alert-error", /Notes/
  end

  test "an auditor can't review their own session" do
    own = make_session(username: "auditor@example.com")
    sign_in_as "auditor"

    get "/console/sessions/#{own.id}"
    assert_select "form[action=?]", "/console/sessions/#{own.id}/audits", count: 0
    assert_select ".bh-hint", /your own session/

    post "/console/sessions/#{own.id}/audits", params: { audit: { status: "approved" } }
    assert_empty own.audits
  end

  test "self audit can be allowed" do
    own = make_session(username: "auditor@example.com")
    sign_in_as "auditor"
    with_config(allow_self_audit: true) do
      post "/console/sessions/#{own.id}/audits", params: { audit: { status: "approved" } }
    end
    assert_equal 1, own.audits.count
  end

  test "staff can't post audits" do
    session = make_session
    sign_in_as "staff"
    post "/console/sessions/#{session.id}/audits", params: { audit: { status: "approved" } }
    assert_response :forbidden
    assert_empty session.audits
  end

  test "pages are never cached" do
    sign_in_as "auditor"
    get "/console"
    assert_equal "no-store", response.headers["Cache-Control"]
  end

  test "SSL can be required" do
    sign_in_as "auditor"
    with_config(require_ssl: true) do
      get "/console"
      assert_response :forbidden
      https!
      get "/console"
      assert_response :success
    end
  end
end
