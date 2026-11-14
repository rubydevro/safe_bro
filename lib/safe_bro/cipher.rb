module SafeBro
  # Recorded commands are encrypted at rest so that someone who can read the database (or a
  # backup) can't read what people typed, which may include customer data.
  module Cipher
    # The encryptor serializes values before encrypting; we only ever pass strings.
    module Raw
      def self.dump(value) = value
      def self.load(value) = value
    end

    class << self
      def encrypt(text)
        return text if text.nil?

        encryptor.encrypt_and_sign(text.to_s)
      end

      def decrypt(cipher_text)
        return cipher_text if cipher_text.nil?

        encryptor.decrypt_and_verify(cipher_text) || "[could not decrypt]"
      rescue ActiveSupport::MessageEncryptor::InvalidMessage, ActiveSupport::MessageVerifier::InvalidSignature
        "[could not decrypt]"
      end

      def reset!
        @encryptor = nil
      end

      private
        def encryptor
          @encryptor ||= ActiveSupport::MessageEncryptor.new(key, cipher: "aes-256-gcm", serializer: Raw)
        end

        def key
          configured = SafeBro.config.encryption_key
          configured = configured.call if configured.respond_to?(:call)
          configured ||= Rails.application.key_generator.generate_key("safe_bro/commands", 32)
          raise Error, "SafeBro encryption_key must be 32 bytes" unless configured.bytesize == 32

          configured
        end
    end
  end
end
