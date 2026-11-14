# Has an encrypted attribute, to check the console shows ciphertext until unlocked.
class Secretive < ApplicationRecord
  encrypts :name
end
