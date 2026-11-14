require "test_helper"
require "pty"
require "timeout"

# Drives a real terminal session: the reason prompt, unlock! with a justification, lock!.
class InteractiveConsoleTest < ActiveSupport::TestCase
  DUMMY = File.expand_path("../dummy", __dir__)
  self.use_transactional_tests = false

  teardown do
    SafeBro::Command.delete_all
    SafeBro::SensitiveAccess.delete_all
    SafeBro::Session.delete_all
  end

  test "asks why, unlocks with a justification, and locks again" do
    env = { "RAILS_ENV" => "test", "SAFE_BRO_E2E" => "1", "SAFE_BRO_E2E_FREEZE" => "1", "CONSOLE_USER" => "jane", "CONSOLE_REASON" => "",
            "SAFE_BRO_E2E_SECRET" => "zzz-secret", "BUNDLE_GEMFILE" => File.expand_path("../../Gemfile", __dir__) }
    transcript = +""

    PTY.spawn(env, "bin/rails", "console", chdir: DUMMY) do |reader, writer, pid|
      say = lambda do |wait_for, input|
        Timeout.timeout(60) { transcript << reader.readpartial(4096) until clean(transcript).match?(wait_for) }
        writer.puts input
      end

      say.(/why are you using this console/, "checking invoice 12")
      say.(/:\d{3}>/, 'ENV["SAFE_BRO_E2E_SECRET"]')
      say.(/Access to env is protected/, "unlock! :env")
      say.(/say why/, "Ticket 99: customer asked")
      say.(/Unlocked\./, 'ENV["SAFE_BRO_E2E_SECRET"]')
      say.(/"zzz-secret"/, "lock!")
      say.(/Locked again/, "exit")
      Process.wait(pid)
    rescue Errno::EIO, PTY::ChildExited
      nil
    end

    session = SafeBro::Session.order(:id).last
    assert_equal "checking invoice 12", session.reason
    assert_not session.open?

    access = session.sensitive_accesses.sole
    assert_equal "env", access.resources
    assert_equal "Ticket 99: customer asked", access.justification
    assert_not_nil access.ended_at

    reads = session.commands.chronological.select { |c| c.statements.include?("SAFE_BRO_E2E_SECRET") }
    assert_nil reads.first.sensitive_access
    assert_equal access, reads.last.sensitive_access
    assert_equal 1, clean(transcript).scan("zzz-secret").size, "the secret should only be printed once, while unlocked"
  end

  private
    def clean(text)
      text.gsub(/\e\[[0-9;?]*[A-Za-z]/, "")
    end
end
