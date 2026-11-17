require "rails/generators"
require "generators/bro_hub/installable"

module SafeBro
  module Generators
    # bin/rails generate safe_bro:install
    class InstallGenerator < Rails::Generators::Base
      # BroHub first (one mount for all the Bro gems), then SafeBro itself.
      include BroHub::Generators::Installable

      source_root File.expand_path("templates", __dir__)

      desc "Sets up the BroHub dashboard (the review UI lives in it), adds the SafeBro initializer and copies its migrations (the shared audit table comes with BroHub)."

      def copy_initializer
        copy_config_once "safe_bro.rb", "config/initializers/safe_bro.rb"
      end

      def copy_migrations
        rails_command "safe_bro:install:migrations", inline: true
      end

      def next_steps
        say <<~TEXT

          SafeBro is installed. Next:
            1. bin/rails db:migrate
            2. Say who may review sessions in config/initializers/safe_bro.rb (config.can_audit)
            3. Make sure every console user arrives with CONSOLE_USER set (see the README)
            4. Visit #{bro_hub_path}/safe_bro (BroHub mounts SafeBro under its own path)
        TEXT
      end
    end
  end
end
