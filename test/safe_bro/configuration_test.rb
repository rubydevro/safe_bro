require "test_helper"

class ConfigurationTest < ActiveSupport::TestCase
  test "enabled by environment" do
    config = SafeBro::Configuration.new
    assert_equal false, config.enabled?
    config.protected_environments = %w[ test ]
    assert config.enabled?
  end

  test "enabled can be forced either way" do
    config = SafeBro::Configuration.new
    config.enabled = true
    assert config.enabled?
    config.protected_environments = %w[ test ]
    config.enabled = false
    assert_not config.enabled?
  end

  test "secret looking ENV names are protected" do
    config = SafeBro::Configuration.new
    %w[ AWS_SECRET_ACCESS_KEY STRIPE_API_KEY DATABASE_URL SECRET_KEY_BASE RAILS_MASTER_KEY MY_PASSWORD ].each do |name|
      assert config.protected_env_name?(name), "#{name} should be protected"
    end
    %w[ HOME PATH RAILS_ENV LANG ].each { |name| assert_not config.protected_env_name?(name), "#{name} should be open" }
  end

  test "lock_down! freezes the lists" do
    config = SafeBro::Configuration.new
    config.lock_down!
    assert config.frozen?
    assert_raises(FrozenError) { config.forbidden_methods << "x" }
    assert_raises(FrozenError) { config.forbidden_constants[:always] << "x" }
    assert_raises(FrozenError) { config.enabled = true }
  end

  test "who is signed in defaults to BroHub's setting, so it only has to be configured once" do
    config = SafeBro::Configuration.new
    controller = Struct.new(:current_user) { public :current_user }.new(Struct.new(:email).new("jane@example.com"))
    assert_equal "jane@example.com", config.current_user.call(controller).email
    assert_equal "jane@example.com", config.user_label.call(controller.current_user)

    original = BroHub.config.current_user
    BroHub.config.current_user = ->(_controller) { :from_bro_hub }
    assert_equal :from_bro_hub, config.current_user.call(controller)
  ensure
    BroHub.config.current_user = original if original
  end
end
