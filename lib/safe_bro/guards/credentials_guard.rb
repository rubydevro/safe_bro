module SafeBro
  module Guards
    # Rails credentials, the keys that open them, and the secret everything is derived from.
    module CredentialsGuard
      # inspect prints the decrypted values once they have been loaded.
      module Inspect
        def inspect
          if SafeBro.executor.executing_user_command? && SafeBro.shield.protects?(:credentials)
            "#<#{self.class.name} [protected]>"
          else
            super
          end
        end
      end

      def self.install
        if defined?(ActiveSupport::EncryptedConfiguration)
          Guarded.install(ActiveSupport::EncryptedConfiguration,
            %i[ read config options [] fetch dig method_missing instance_variable_get ], :credentials,
            inherited: %i[ instance_variable_get ])
          ActiveSupport::EncryptedConfiguration.prepend(Inspect)
        end
        if defined?(ActiveSupport::EncryptedFile)
          Guarded.install(ActiveSupport::EncryptedFile, %i[ read write change key read_env_key read_key_file ], :credentials)
        end
        Guarded.install(Rails::Application, %i[ secret_key_base secrets key_generator message_verifier message_verifiers ], :credentials)
        Guarded.install(Rails::Application::Configuration, %i[ secret_key_base ], :credentials)
      end
    end
  end
end
