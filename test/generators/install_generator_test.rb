require "test_helper"
require "generators/safe_bro/install/install_generator"

class SafeBro::Generators::InstallGeneratorTest < Rails::Generators::TestCase
  tests SafeBro::Generators::InstallGenerator
  destination File.expand_path("../../tmp/generator_test", __dir__)

  setup do
    prepare_destination
    FileUtils.mkdir_p File.join(destination_root, "config")
    File.write(File.join(destination_root, "config/routes.rb"), "Rails.application.routes.draw do\nend\n")
  end

  test "creates the initializer with nobody allowed to audit" do
    run_install
    assert_file "config/initializers/safe_bro.rb", /config\.can_audit = ->\(user\) \{ false \}/
  end

  test "sets up BroHub instead of mounting SafeBro itself" do
    run_install
    assert_file "config/initializers/bro_hub.rb"
    assert_file "config/routes.rb" do |content|
      assert_match %r{mount BroHub::Engine => "/bro_hub"}, content
      assert_no_match(/SafeBro::Engine/, content)
    end
  end

  test "mounts BroHub at --mount-path, normalizing slashes" do
    run_install "--mount-path=ops/bro/"
    assert_file "config/routes.rb", %r{mount BroHub::Engine => "/ops/bro"}
  end

  test "does not mount BroHub twice" do
    run_install
    run_install "--mount-path=/other"
    assert_file "config/routes.rb" do |content|
      assert_equal 1, content.scan("BroHub::Engine").size
    end
  end

  test "says where SafeBro ended up" do
    output = run_install "--mount-path=/ops/bro"
    assert_match %r{/ops/bro/safe_bro}, output
  end

  private
    # Migrations are copied by the engine's rake task, which needs a real host app.
    def run_install(*args)
      install = generator([], args, destination_root: destination_root)
      def install.copy_migrations; end
      capture(:stdout) { install.invoke_all }
    end
end
