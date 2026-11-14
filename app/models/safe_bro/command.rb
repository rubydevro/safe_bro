require "safe_bro/encrypted_type"

module SafeBro
  class Command < ApplicationRecord
    belongs_to :session
    belongs_to :sensitive_access, optional: true

    attribute :statements, SafeBro::EncryptedType.new

    # executed: ran normally. suspicious: ran, but flagged. blocked: never ran.
    enum :status, { executed: 0, suspicious: 1, blocked: 2 }

    scope :flagged, -> { where(status: [ statuses[:suspicious], statuses[:blocked] ]) }
    scope :chronological, -> { order(:created_at, :id) }

    def flagged?
      suspicious? || blocked?
    end
  end
end
