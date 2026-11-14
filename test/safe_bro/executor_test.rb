require "test_helper"

class ExecutorTest < ActiveSupport::TestCase
  def last_command(session)
    session.commands.chronological.last
  end

  test "commands are recorded before they run, in order" do
    with_session do |session|
      typed "a = 1"
      typed "a + 1"
      assert_equal [ "a = 1", "a + 1" ], session.commands.chronological.map(&:statements)
      assert session.commands.all?(&:executed?)
    end
  end

  test "a crashing command is recorded and the error propagates" do
    with_session do |session|
      assert_raises(ZeroDivisionError) { typed "1 / 0" }
      assert_equal "1 / 0", last_command(session).statements
      assert last_command(session).executed?
    end
  end

  test "forbidden commands are blocked, recorded and flagged" do
    with_session do |session|
      error = assert_raises(SafeBro::ForbiddenCommand) { typed "$ran = true; eval('1')" }
      assert_match "eval", error.message
      assert_nil $ran
      assert last_command(session).blocked?
      assert_match "eval", last_command(session).flag_reason
    end
  end

  test "suspicious commands run but are flagged" do
    with_session do |session|
      assert_equal "ok", typed("ENV.fetch('SAFE_BRO_UNSET_VAR', 'ok')")
      assert last_command(session).suspicious?
    end
  end

  test "methods called indirectly are caught at runtime" do
    with_session do |session|
      assert_raises(SafeBro::ForbiddenCommand) { typed "Kernel.send('ev' + 'al', '1 + 1')" }
      assert last_command(session).blocked?
      assert_raises(SafeBro::ForbiddenCommand) { typed "Object.new.instance_exec(&->(*) { 1 })" }
    end
  end

  test "the same methods work for library code" do
    with_session do
      assert_equal 2, SafeBro.executor.run_as_user { eval("1 + 1") }
      assert_equal 3, SafeBro.executor.run_as_user { Object.new.instance_eval { 3 } }
    end
  end

  test "constants built from strings are caught" do
    with_session do |session|
      assert_raises(SafeBro::ForbiddenCommand) { typed "Object.const_get('Safe' + 'Bro')" }
      assert_raises(SafeBro::ForbiddenCommand) { typed "('Safe' + 'Bro').constantize" }
      assert_raises(SafeBro::ForbiddenCommand) { typed "('Safe' + 'Bro').safe_constantize" }
      assert session.commands.all?(&:blocked?)
    end
  end

  test "harmless dynamic constants still work" do
    with_session do
      assert_equal String, typed("Object.const_get('Str' + 'ing')")
      assert_equal User, typed("'User'.constantize")
    end
  end

  test "the audit trail can't be touched from the console" do
    with_session do |session|
      original = session.commands.create!(statements: "x")
      %w[ safe_bro_commands safe_bro_sessions safe_bro_audits safe_bro_sensitive_accesses ].each do |table|
        assert_raises(SafeBro::TamperingAttempt) { typed "ActiveRecord::Base.connection.execute('DELETE FROM #{table}')" }
        assert_raises(SafeBro::TamperingAttempt) { typed "ActiveRecord::Base.connection.select_all('SELECT * FROM #{table}')" }
      end
      assert SafeBro::Command.exists?(original.id)
      assert session.commands.where.not(id: original.id).all?(&:blocked?)
    end
  end

  test "messages are built under protection" do
    with_session do
      error = assert_raises(RuntimeError) { typed "raise 'boom'" }
      assert_equal "boom", error.message
      assert_equal "boom", error.to_s
    end
  end

  test "outside a command nothing is guarded" do
    assert_equal 2, eval("1 + 1")
    assert_not SafeBro.executor.executing_user_command?
  end

  test "run_as_system turns the user flag off inside run_as_user" do
    SafeBro.executor.run_as_user do
      assert SafeBro.executor.executing_user_command?
      SafeBro.executor.run_as_system { assert_not SafeBro.executor.executing_user_command? }
      assert SafeBro.executor.executing_user_command?
    end
  end

  test "from_console? only trusts the irb file" do
    SafeBro.executor.run_as_user do
      assert SafeBro.executor.from_console?([ Struct.new(:path).new("(irb)") ])
      assert_not SafeBro.executor.from_console?([ Struct.new(:path).new("/app/models/user.rb") ])
    end
    assert_not SafeBro.executor.from_console?([ Struct.new(:path).new("(irb)") ])
  end
end
