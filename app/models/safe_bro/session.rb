module SafeBro
  # One console session: who, why, from where, and everything they did.
  class Session < ApplicationRecord
    has_many :commands, dependent: :delete_all
    has_many :sensitive_accesses, dependent: :delete_all
    has_many :audits, dependent: :delete_all

    # The latest audit decides the status.
    enum :review_status, { pending: 0, approved: 1, flagged: 2 }, prefix: :review

    validates :username, :reason, :started_at, presence: true

    scope :chronological, -> { order(started_at: :desc, id: :desc) }
    scope :on_or_after, ->(time) { where(started_at: time..) }
    scope :before, ->(time) { where(started_at: ...time) }

    # Sessions that deserve a look: someone unlocked sensitive data or a command was flagged.
    scope :needing_attention, -> {
      where(id: SensitiveAccess.select(:session_id)).or(where(id: Command.flagged.select(:session_id)))
    }

    # Sessions that nobody has audited, and aren't empty housekeeping.
    scope :awaiting_review, -> { where(review_status: :pending) }

    class << self
      # Deletes old sessions and everything under them. Flagged ones stay unless told otherwise.
      def purge!(older_than: SafeBro.config.retention, keep_flagged: SafeBro.config.keep_flagged)
        return 0 if older_than.nil?

        scope = where(started_at: ...older_than.ago)
        scope = scope.where.not(review_status: :flagged) if keep_flagged
        scope.find_each.sum { |session| session.destroy ? 1 : 0 }
      end
    end

    def sensitive?
      sensitive_accesses.exists? || commands.flagged.exists?
    end

    def open?
      ended_at.nil?
    end

    def duration
      ((ended_at || Time.current) - started_at).to_i
    end

    def last_audit
      audits.order(:id).last
    end
  end
end
