require "test_helper"

# SafeBro as a section of the BroHub dashboard (mounted at /bro_hub in the dummy app).
class BroHubIntegrationTest < ActionDispatch::IntegrationTest
  def sign_in_as(role)
    post "/role", params: { role: role }
  end

  def make_session(username: "alice", reason: "fix invoice", started: Time.current)
    SafeBro::Session.create!(username: username, reason: reason, started_at: started)
  end

  test "the hub sends an auditor to SafeBro, and keeps everyone else out" do
    get "/bro_hub"
    assert_response :forbidden

    sign_in_as "staff"
    get "/bro_hub"
    assert_response :forbidden
    get "/bro_hub/safe_bro"
    assert_response :forbidden
    assert_select ".bh-group-label", text: /SafeBro/, count: 0

    sign_in_as "auditor"
    get "/bro_hub"
    assert_redirected_to "/bro_hub/safe_bro"
  end

  test "SafeBro renders inside the shell with its own sidebar section" do
    make_session
    sign_in_as "auditor"
    get "/bro_hub/safe_bro"
    assert_response :success
    assert_select ".bh-top .bh-user", "auditor@example.com"
    assert_select ".bh-group-label", "SafeBro · audit"
    assert_select "a.bh-nav.is-active[href='/bro_hub/safe_bro']", /Sessions/
    assert_select "a.bh-nav[href='/bro_hub/safe_bro/flagged']"
    assert_select "a.bh-nav[href='/bro_hub/safe_bro/unlocks']"
    assert_select "a.bh-nav[href='/bro_hub/safe_bro/rules']"
    assert_select ".bh-crumb", /SafeBro \/ Console sessions/
  end

  test "the sidebar badge counts sessions waiting for a verdict" do
    2.times { make_session }
    make_session.audits.create!(auditor: "bob", status: :approved)
    sign_in_as "auditor"
    get "/bro_hub/safe_bro/rules"
    assert_select "a.bh-nav[href='/bro_hub/safe_bro'] .bh-badge", "2"
  end

  test "links and the audit form work under the hub's mount point" do
    first = make_session(reason: "first", started: 2.hours.ago)
    second = make_session(reason: "second", started: 1.hour.ago)
    sign_in_as "auditor"

    get "/bro_hub/safe_bro"
    assert_select "a.bh-row[href^='/bro_hub/safe_bro/sessions/#{second.id}']"

    get "/bro_hub/safe_bro/sessions/#{second.id}"
    assert_select "form[action=?]", "/bro_hub/safe_bro/sessions/#{second.id}/audits"
    assert_select ".bh-crumb-actions a", /All sessions/

    post "/bro_hub/safe_bro/sessions/#{second.id}/audits", params: { audit: { status: "approved" }, filter_status: "pending" }
    assert_redirected_to "/bro_hub/safe_bro/sessions/#{first.id}?status=pending"
  end

  test "the review tabs keep the other filters" do
    sign_in_as "auditor"
    get "/bro_hub/safe_bro", params: { username: "dave", status: "pending" }
    assert_select ".bh-crumb-actions a.is-active", "Pending"
    assert_select ".bh-crumb-actions a[href*='username=dave'][href*='status=flagged']", "Flagged"
  end

  test "a directly mounted SafeBro still works, with just its own section" do
    sign_in_as "auditor"
    get "/console"
    assert_response :success
    assert_select ".bh-group-label", "SafeBro · audit"
    assert_select ".bh-group-label", count: 1
    assert_select "a.bh-nav.is-active[href='/console']"
    assert_select "a.bh-nav[href='/console/flagged']"
  end

  test "flagged commands lists blocked and suspicious ones, newest first, linking to the session" do
    session = make_session(username: "carol")
    session.commands.create!(statements: "puts 1")
    older = session.commands.create!(statements: "ENV['X']", status: :suspicious, flag_reason: "Command mentions ENV.", created_at: 2.hours.ago)
    newer = session.commands.create!(statements: "eval('x')", status: :blocked, flag_reason: "Calling eval is not allowed.", created_at: 1.hour.ago)

    sign_in_as "auditor"
    get "/bro_hub/safe_bro/flagged"
    assert_response :success
    assert_select ".bh-title", /2\s+commands/
    rows = css_select("a.bh-row").map(&:text)
    assert_equal 2, rows.size
    assert_match(/eval/, rows.first)
    assert_match(/ENV/, rows.last)
    assert_no_match(/puts 1/, response.body)
    assert_select "a.bh-row[href='/bro_hub/safe_bro/sessions/#{session.id}']", 2
    assert_select ".bh-status", text: "Blocked"
    assert_select ".bh-status", text: "Ran"
    assert_operator newer.created_at, :>, older.created_at
  end

  test "unlocks lists who unlocked what and why" do
    session = make_session(username: "erin")
    access = session.sensitive_accesses.create!(justification: "Ticket 9 asked for it", resources: "credentials", started_at: Time.current)
    session.commands.create!(statements: "x", sensitive_access: access)

    sign_in_as "auditor"
    get "/bro_hub/safe_bro/unlocks"
    assert_response :success
    assert_select ".bh-title", /1\s+unlock/
    assert_select "a.bh-row", /erin/
    assert_select "a.bh-row", /Ticket 9 asked for it/
    assert_select "a.bh-row .bh-tag.is-amber", "credentials"
    assert_select "a.bh-row .bh-tag", text: "open"
  end

  test "rules shows the effective configuration without secrets" do
    with_config(protected_urls: [ "redis://:hunter2@cache.internal:6379" ], encryption_key: "k" * 32) do
      sign_in_as "auditor"
      get "/bro_hub/safe_bro/rules"
      assert_response :success
      assert_select ".bh-tag", "SafeBro"
      assert_select ".bh-tag", "Kernel#eval"
      assert_select ".bh-tag", "cache.internal:6379"
      assert_no_match(/hunter2/, response.body)
      assert_no_match(/#{"k" * 32}/, response.body)
    end
  end

  test "the new pages need the same permission as the sessions" do
    %w[ flagged unlocks rules ].each do |page|
      get "/bro_hub/safe_bro/#{page}"
      assert_response :forbidden, "#{page} should be closed to nobody"
    end

    sign_in_as "staff"
    %w[ flagged unlocks rules ].each do |page|
      get "/bro_hub/safe_bro/#{page}"
      assert_response :forbidden, "#{page} should be closed to staff"
    end
  end

  test "the new pages are paged" do
    session = make_session
    (SafeBro::ApplicationHelper::PER_PAGE + 1).times { |i| session.commands.create!(statements: "c#{i}", status: :suspicious, flag_reason: "r") }
    sign_in_as "auditor"
    get "/bro_hub/safe_bro/flagged"
    assert_select "a.bh-row", SafeBro::ApplicationHelper::PER_PAGE
    assert_select "a", "Older →"
    get "/bro_hub/safe_bro/flagged", params: { page: 1 }
    assert_select "a.bh-row", 1
    assert_select "a", "← Newer"
  end
end
