# Configure Rails Environment
ENV["RAILS_ENV"] = "test"

require_relative "../test/dummy/config/environment"
require "rails/test_help"

# Load the dummy schema into the test database on every run (cheap with SQLite).
ActiveRecord::Schema.verbose = false
load File.expand_path("dummy/db/schema.rb", __dir__)

# Installs the guards process-wide. They do nothing unless a console command is executing.
SafeBro.config.protected_urls = [ "tcp://127.0.0.1:9" ]
SafeBro.shield.install
SafeBro::Terminal.muted = true

class ActiveSupport::TestCase
  setup do
    SafeBro::Audit.delete_all
    SafeBro::Command.delete_all
    SafeBro::SensitiveAccess.delete_all
    SafeBro::Session.delete_all
    Secretive.delete_all
    SafeBro.shield.lock(silent: true)
  end

  # Sets config values for the block, then puts them back.
  def with_config(**values)
    originals = values.keys.index_with { |name| SafeBro.config.public_send(name) }
    values.each { |name, value| SafeBro.config.public_send(:"#{name}=", value) }
    yield
  ensure
    originals.each { |name, value| SafeBro.config.public_send(:"#{name}=", value) }
  end

  # Starts a recorded session for the block, as if someone had opened a console.
  def with_session(username: "alice", reason: "testing")
    SafeBro.recorder.start_session(username: username, reason: reason)
    yield SafeBro.recorder.session
  ensure
    SafeBro.recorder.finish_session
  end

  # Runs the block the way the console would run typed code, from the "(irb)" file.
  def typed(code, &)
    SafeBro.executor.execute(Array(code)) { eval(code, TOPLEVEL_BINDING, "(irb)", 1) }
  end

  # Replaces object.name for the block (no mocking library needed).
  def stubbing(object, name, value)
    original = object.method(name)
    object.define_singleton_method(name) { |*, **| value }
    yield
  ensure
    object.define_singleton_method(name, original)
  end

  # Unlocks without a terminal: answers the question for the person.
  def unlock(*resources, justification: "ticket 123")
    stubbing(SafeBro::Terminal, :ask, justification) { SafeBro.shield.unlock(resources.presence || [ :all ]) }
  end
end
