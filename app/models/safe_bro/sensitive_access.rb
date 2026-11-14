module SafeBro
  # A window during which the console was unlocked, with the justification given for it.
  class SensitiveAccess < ApplicationRecord
    belongs_to :session
    has_many :commands, dependent: :nullify

    validates :justification, :resources, :started_at, presence: true

    def open?
      ended_at.nil?
    end
  end
end
