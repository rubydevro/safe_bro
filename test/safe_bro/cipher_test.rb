require "test_helper"

class CipherTest < ActiveSupport::TestCase
  test "round trips text" do
    cipher_text = SafeBro::Cipher.encrypt("User.find(1).ssn")
    assert_not_includes cipher_text, "ssn"
    assert_equal "User.find(1).ssn", SafeBro::Cipher.decrypt(cipher_text)
  end

  test "garbage does not decrypt" do
    assert_equal "[could not decrypt]", SafeBro::Cipher.decrypt("not encrypted")
  end

  test "nil stays nil" do
    assert_nil SafeBro::Cipher.encrypt(nil)
    assert_nil SafeBro::Cipher.decrypt(nil)
  end

  test "commands are encrypted at rest" do
    with_session do |session|
      session.commands.create!(statements: "Customer.last.card_number")
      raw = ActiveRecord::Base.connection.select_value("SELECT statements FROM safe_bro_commands")
      assert_not_includes raw, "card_number"
      assert_equal "Customer.last.card_number", session.commands.last.statements
    end
  end

  test "an explicit key is used and must be 32 bytes" do
    with_config(encryption_key: "short") do
      SafeBro::Cipher.reset!
      assert_raises(SafeBro::Error) { SafeBro::Cipher.encrypt("x") }
    end
  ensure
    SafeBro::Cipher.reset!
  end
end
