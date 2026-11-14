require "test_helper"
require "tmpdir"

class ResourcesTest < ActiveSupport::TestCase
  setup { ENV["SAFE_BRO_TEST_SECRET"] = "s3cr3t" }
  teardown { ENV.delete("SAFE_BRO_TEST_SECRET") }

  # --- ENV -------------------------------------------------------------------------------

  test "reading a secret ENV variable by name is blocked, and flagged" do
    with_session do |session|
      assert_raises(SafeBro::ProtectedResource) { typed "ENV['SAFE_BRO_TEST_SECRET']" }
      assert_raises(SafeBro::ProtectedResource) { typed "ENV.fetch('SAFE_BRO_TEST_SECRET')" }
      assert_raises(SafeBro::ProtectedResource) { typed "ENV.values_at('HOME', 'SAFE_BRO_TEST_SECRET')" }
      assert_raises(SafeBro::ProtectedResource) { typed "ENV.slice('SAFE_BRO_TEST_SECRET')" }
      assert session.commands.all?(&:suspicious?)
    end
  end

  test "other ENV variables are readable" do
    with_session { assert_equal ENV["HOME"], typed("ENV['HOME']") }
  end

  test "dumping ENV filters the secrets" do
    with_session do
      dumped = typed("ENV.to_h")
      assert_equal "[FILTERED]", dumped["SAFE_BRO_TEST_SECRET"]
      assert_equal ENV["HOME"], dumped["HOME"]
      assert_equal "[FILTERED]", typed("ENV.to_hash")["SAFE_BRO_TEST_SECRET"]
      assert_equal "[FILTERED]", typed("ENV.select { true }")["SAFE_BRO_TEST_SECRET"]
      assert_equal "[FILTERED]", typed("ENV.each_pair.to_h")["SAFE_BRO_TEST_SECRET"]
      assert_not_includes typed("ENV.inspect"), "s3cr3t"
      assert_not_includes SafeBro.executor.execute_in_protected_mode { ENV.inspect }.to_s, "s3cr3t" if false
    end
  end

  test "unlocked, ENV is readable" do
    with_session do
      unlock :env
      assert_equal "s3cr3t", typed("ENV['SAFE_BRO_TEST_SECRET']")
      assert_equal "s3cr3t", typed("ENV.to_h")["SAFE_BRO_TEST_SECRET"]
    end
  end

  test "library code reads ENV freely, even during a command" do
    with_session do
      assert_equal "s3cr3t", SafeBro.executor.run_as_user { ENV["SAFE_BRO_TEST_SECRET"] }
      assert_equal "s3cr3t", ENV["SAFE_BRO_TEST_SECRET"]
    end
  end

  # --- Credentials ---------------------------------------------------------------------------

  test "credentials can't be read from the console" do
    with_session do |session|
      assert_raises(SafeBro::ProtectedResource) { typed "Rails.application.credentials.anything" }
      assert_raises(SafeBro::ProtectedResource) { typed "Rails.application.credentials[:anything]" }
      assert_raises(SafeBro::ProtectedResource) { typed "Rails.application.credentials.config" }
      assert_raises(SafeBro::ProtectedResource) { typed "Rails.application.credentials.dig(:a, :b)" }
      assert_raises(SafeBro::ProtectedResource) { typed "Rails.application.credentials.read" }
      assert_raises(SafeBro::ProtectedResource) { typed "Rails.application.credentials.instance_variable_get(:@config)" }
      assert_raises(SafeBro::ProtectedResource) { typed "Rails.application.secret_key_base" }
      assert_raises(SafeBro::ProtectedResource) { typed "Rails.application.key_generator" }
      assert_raises(SafeBro::ProtectedResource) { typed "Rails.application.config.secret_key_base" }
      assert session.commands.all?(&:suspicious?)
    end
  end

  test "inspecting the credentials object doesn't print its contents" do
    credentials = Rails.application.credentials
    assert_match "protected", SafeBro.executor.run_as_user { credentials.inspect }
    assert_no_match(/protected/, credentials.inspect)
  end

  test "credentials are readable when unlocked" do
    with_session do
      unlock :credentials
      assert_equal Rails.application.secret_key_base, typed("Rails.application.secret_key_base")
      assert_nothing_raised { typed "Rails.application.credentials.anything" }
    end
  end

  test "library code can still use credentials during a command" do
    with_session do
      SafeBro.executor.run_as_user do
        assert_nothing_raised { Rails.application.credentials.anything }
        assert_nothing_raised { Rails.application.secret_key_base }
      end
    end
  end

  # --- Files ------------------------------------------------------------------------------------

  test "key and env files can't be read from the console" do
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p File.join(dir, "config/credentials")
      master = File.join(dir, "config/master.key")
      env_specific = File.join(dir, "config/credentials/production.key")
      dotenv = File.join(dir, ".env.production")
      [ master, env_specific, dotenv ].each { |path| File.write(path, "topsecret") }

      with_session do
        [ master, env_specific, dotenv ].each do |path|
          assert_raises(SafeBro::ProtectedResource, path) { typed "File.read(#{path.inspect})" }
          assert_raises(SafeBro::ProtectedResource, path) { typed "File.open(#{path.inspect}).read" }
          assert_raises(SafeBro::ProtectedResource, path) { typed "IO.readlines(#{path.inspect})" }
          assert_raises(SafeBro::ProtectedResource, path) { typed "File.binread(#{path.inspect})" }
          assert_raises(SafeBro::ProtectedResource, path) { typed "Pathname.new(#{path.inspect}).read" }
          assert_raises(SafeBro::ProtectedResource, path) { typed "open(#{path.inspect}).read" }
          assert_raises(SafeBro::ProtectedResource, path) { typed "FileUtils.cp(#{path.inspect}, #{path.inspect}.to_s + '.copy')" }
          assert_raises(SafeBro::ProtectedResource, path) { typed "File.new(#{path.inspect})" }
        end

        unlock :files
        assert_equal "topsecret", typed("File.read(#{master.inspect})")
      end
    end
  end

  test "other files are readable" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "notes.txt")
      File.write(path, "hi")
      with_session { assert_equal "hi", typed("File.read(#{path.inspect})") }
    end
  end

  test "library code can read key files" do
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p File.join(dir, "config")
      path = File.join(dir, "config/master.key")
      File.write(path, "k")
      with_session { assert_equal "k", SafeBro.executor.run_as_user { File.read(path) } }
    end
  end

  # --- Network ----------------------------------------------------------------------------------

  test "protected systems can't be reached while locked" do
    server = TCPServer.new("127.0.0.1", 0)
    port = server.addr[1]
    with_config(protected_urls: [ "redis://127.0.0.1:#{port}" ]) do
      SafeBro::Guards::NetworkGuard.reset!

      # Outside a command: fine.
      TCPSocket.new("127.0.0.1", port).close

      with_session do |session|
        assert_raises(SafeBro::ProtectedResource) { typed "TCPSocket.new('127.0.0.1', #{port})" }
        assert_raises(SafeBro::ProtectedResource) { typed "Socket.tcp('127.0.0.1', #{port}) { }" }
        assert session.commands.all?(&:suspicious?)

        # A connection opened earlier (a pool) is caught when written to.
        existing = TCPSocket.new("127.0.0.1", port)
        assert_raises(SafeBro::ProtectedResource) { SafeBro.executor.run_as_user { existing.write("PING") } }
        existing.close

        # Other ports are not protected.
        other = TCPServer.new("127.0.0.1", 0)
        assert_nothing_raised { typed("TCPSocket.new('127.0.0.1', #{other.addr[1]}).close") }
        other.close

        unlock :network
        assert_nothing_raised { typed("TCPSocket.new('127.0.0.1', #{port}).close") }
      end
    end
  ensure
    SafeBro::Guards::NetworkGuard.reset!
    server&.close
  end
end
