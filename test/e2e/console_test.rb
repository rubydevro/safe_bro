require "test_helper"
require "open3"

# Boots a real `rails console` in the dummy app, with commands piped in, and checks what was
# recorded. This is the test that proves the IRB hook works on the IRB we're running.
class ConsoleTest < ActiveSupport::TestCase
  DUMMY = File.expand_path("../dummy", __dir__)

  # The console process writes to the same SQLite file, so this test can't hold a transaction open.
  self.use_transactional_tests = false

  teardown do
    SafeBro::Command.delete_all
    SafeBro::SensitiveAccess.delete_all
    SafeBro::Session.delete_all
  end

  def run_console(input, env = {})
    env = { "RAILS_ENV" => "test", "SAFE_BRO_E2E" => "1", "SAFE_BRO_E2E_FREEZE" => "1", "CONSOLE_USER" => "jane", "CONSOLE_REASON" => "e2e check",
            "SAFE_BRO_E2E_SECRET" => "e2e-secret-value", "BUNDLE_GEMFILE" => File.expand_path("../../Gemfile", __dir__) }.merge(env)
    Open3.capture3(env, "bin/rails", "console", stdin_data: input, chdir: DUMMY)
  end

  test "a console session is recorded, guarded, and closed" do
    out, err, = run_console(<<~RUBY)
      1 + 1
      ENV["SAFE_BRO_E2E_SECRET"]
      ENV.to_h["SAFE_BRO_E2E_SECRET"]
      eval("2 + 2")
      SafeBro.config
      Rails.application.secret_key_base
      Kernel.send("ev" + "al", "3 + 3")
      Object.const_get("Safe" + "Bro")
      unlock!
      puts "done"
    RUBY

    session = SafeBro::Session.order(:id).last
    assert_equal "jane", session.username
    assert_equal "e2e check", session.reason
    assert_not session.open?, "session should be closed at exit.\n#{err}"

    commands = session.commands.chronological.index_by(&:statements)
    assert commands["1 + 1"].executed?
    assert commands['ENV["SAFE_BRO_E2E_SECRET"]'].suspicious?
    assert commands['eval("2 + 2")'].blocked?
    assert commands["SafeBro.config"].blocked?
    assert commands["Rails.application.secret_key_base"].suspicious?
    assert commands["Kernel.send(\"ev\" + \"al\", \"3 + 3\")"].blocked?
    assert commands["Object.const_get(\"Safe\" + \"Bro\")"].blocked?
    assert commands["unlock!"], "unlock! should be recorded"

    assert_includes out, "2"
    assert_includes out, "done"
    assert_includes out + err, "Access to env is protected"
    assert_not_includes out + err, "e2e-secret-value", "the secret leaked to the terminal"
    assert_not_includes out + err, Rails.application.secret_key_base, "secret_key_base leaked to the terminal"
    assert_not_includes out, "=> 6"
    assert_includes out + err, "interactive terminal", "unlock! needs a terminal to ask on"
    assert_empty session.sensitive_accesses
  end

  test "SafeBro's classes and config are frozen in the real console, and can't be reopened" do
    out, err, = run_console(<<~RUBY)
      SafeBro::Executor.frozen?
      Kernel.send(:eval, "1")
      class SafeBro::Executor; def execute(*) = yield; end
      puts "still-running"
    RUBY
    assert_includes out, "still-running"
    session = SafeBro::Session.order(:id).last
    assert session.commands.where(status: :blocked).count >= 2, "#{out}\n#{err}"
  end

  test "the console refuses to start without knowing who you are" do
    out, err, status = run_console("1 + 1\n", "CONSOLE_USER" => "")
    assert_not status.success?
    assert_includes out + err, "CONSOLE_USER"
    assert_empty SafeBro::Session.all
  end

  test "the console refuses to start without a reason when there is no terminal" do
    out, err, status = run_console("1 + 1\n", "CONSOLE_REASON" => "")
    assert_not status.success?
    assert_includes out + err, "CONSOLE_REASON"
    assert_empty SafeBro::Session.all
  end

  test "rails runner sessions are recorded when enabled" do
    env = { "RAILS_ENV" => "test", "SAFE_BRO_E2E" => "1", "SAFE_BRO_E2E_RUNNER" => "1", "CONSOLE_USER" => "ci",
            "CONSOLE_REASON" => "nightly task", "BUNDLE_GEMFILE" => File.expand_path("../../Gemfile", __dir__) }
    _, err, status = Open3.capture3(env, "bin/rails", "runner", "puts 1 + 1", chdir: DUMMY)
    assert status.success?, err

    session = SafeBro::Session.order(:id).last
    assert_equal "runner", session.source
    assert_equal "ci", session.username
    assert_equal "nightly task", session.reason
    assert_match "puts 1 + 1", session.commands.sole.statements
    assert_not session.open?
  end
end
