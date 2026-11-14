require "test_helper"

class ShieldTest < ActiveSupport::TestCase
  test "starts locked" do
    assert SafeBro.shield.locked?
    assert SafeBro.shield.protects?(:credentials)
  end

  test "unlock records the justification and links the commands typed while unlocked" do
    with_session do |session|
      typed "before = 1"
      unlock justification: "Ticket 42: customer asked"
      typed "during = 2"
      SafeBro.shield.lock(silent: true)
      typed "after = 3"

      access = session.sensitive_accesses.sole
      assert_equal "Ticket 42: customer asked", access.justification
      assert_equal "all", access.resources
      assert_not_nil access.ended_at

      by_text = session.commands.index_by(&:statements)
      assert_nil by_text["before = 1"].sensitive_access
      assert_equal access, by_text["during = 2"].sensitive_access
      assert_nil by_text["after = 3"].sensitive_access
    end
  end

  test "unlock can be limited to some resources" do
    with_session do
      unlock :credentials
      assert SafeBro.shield.unlocked?(:credentials)
      assert_not SafeBro.shield.unlocked?(:env)
      assert SafeBro.shield.protects?(:env)
    end
  end

  test "unlock all opens everything" do
    with_session do
      unlock
      SafeBro::Shield::RESOURCES.each { |resource| assert SafeBro.shield.unlocked?(resource) }
    end
  end

  test "unknown resources are rejected" do
    with_session do
      error = assert_raises(ArgumentError) { SafeBro.shield.unlock([ :bogus ]) }
      assert_match "credentials", error.message
      assert SafeBro.shield.locked?
    end
  end

  test "unlocking needs somebody to answer" do
    with_session do
      stubbing($stdin, :tty?, false) do
        assert_raises(SafeBro::NotInteractive) { SafeBro.shield.unlock([ :all ]) }
      end
      assert SafeBro.shield.locked?
      assert_empty SafeBro::SensitiveAccess.all
    end
  end

  test "a new unlock closes the previous window" do
    with_session do |session|
      unlock :env, justification: "first"
      unlock :files, justification: "second"
      assert_equal [ "first", "second" ], session.sensitive_accesses.order(:id).map(&:justification)
      assert_not_nil session.sensitive_accesses.order(:id).first.ended_at
      assert_nil session.sensitive_accesses.order(:id).last.ended_at
    end
  end

  test "unlocking notifies" do
    events = []
    subscriber = ActiveSupport::Notifications.subscribe("unlocked.safe_bro") { |*, payload| events << payload }
    with_session { unlock justification: "why" }
    assert_equal "why", events.sole[:access].justification
  ensure
    ActiveSupport::Notifications.unsubscribe(subscriber)
  end

  test "encrypted attributes read as ciphertext until unlocked" do
    Secretive.create!(name: "hunter2")
    with_session do
      shown = typed("Secretive.first.name")
      assert_not_equal "hunter2", shown
      assert_not_includes shown, "hunter2"

      unlock :encrypted_data
      assert_equal "hunter2", typed("Secretive.first.name")
    end
  end

  test "encrypted attributes can't be written while locked" do
    record = Secretive.create!(name: "hunter2")
    with_session do
      assert_raises(StandardError) { typed "Secretive.first.update!(name: 'changed')" }
    end
    assert_equal "hunter2", record.reload.name
  end

  test "SafeBro.guard! protects custom resources" do
    with_config(protected_resources: SafeBro.config.protected_resources + [ :billing ]) do
      with_session do
        assert_nothing_raised { SafeBro.guard!(:billing) } # not in a console command
        SafeBro.executor.run_as_user do
          error = assert_raises(SafeBro::ProtectedResource) { SafeBro.guard!(:billing, "(invoices)") }
          assert_equal :billing, error.resource
          assert_match "invoices", error.message
        end
        unlock :billing
        SafeBro.executor.run_as_user { assert_nothing_raised { SafeBro.guard!(:billing) } }
      end
    end
  end

  test "resources not in protected_resources are never protected" do
    with_config(protected_resources: [ :env ]) do
      assert_not SafeBro.shield.protects?(:credentials)
      assert SafeBro.shield.protects?(:env)
    end
  end
end
