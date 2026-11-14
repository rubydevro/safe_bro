module SafeBro
  # ActiveRecord attribute type that stores text encrypted with SafeBro::Cipher.
  class EncryptedType < ActiveRecord::Type::Text
    def serialize(value)
      super(value.nil? ? nil : Cipher.encrypt(value))
    end

    def deserialize(value)
      value.nil? ? nil : Cipher.decrypt(super)
    end

    def changed_in_place?(raw_old_value, new_value)
      deserialize(raw_old_value) != new_value
    end
  end
end
