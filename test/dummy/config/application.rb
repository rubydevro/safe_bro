require_relative "boot"

require "rails"
require "active_model/railtie"
require "active_job/railtie"
require "active_record/railtie"
require "action_controller/railtie"
require "action_view/railtie"
require "rails/test_unit/railtie"

Bundler.require(*Rails.groups)

module Dummy
  class Application < Rails::Application
    config.load_defaults Rails::VERSION::STRING.to_f
    config.action_controller.include_all_helpers = false
    config.autoload_lib(ignore: %w[assets tasks])

    # Active Record encryption, to test the encrypted_data protection.
    config.active_record.encryption.primary_key = "test-primary-key-for-safe-bro-dummy"
    config.active_record.encryption.deterministic_key = "test-deterministic-key-for-dummy"
    config.active_record.encryption.key_derivation_salt = "test-key-derivation-salt-for-dummy"

    config.secret_key_base = "dummy-secret-key-base-for-safe-bro-tests-0123456789"
  end
end
