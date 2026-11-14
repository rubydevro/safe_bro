require "safe_bro/encrypted_type"

module SafeBro
  # An auditor's verdict on a session. Audits are append-only: re-auditing adds a new row,
  # so the history of who decided what is kept.
  class Audit < ApplicationRecord
    belongs_to :session

    enum :status, { approved: 1, flagged: 2 }

    attribute :notes, SafeBro::EncryptedType.new

    validates :auditor, presence: true
    validates :notes, presence: true, if: :flagged?

    after_create { session.update!(review_status: status) }
    after_create { SafeBro.notify(:session_flagged, session: session, auditor: auditor, notes: notes) if flagged? }
  end
end
