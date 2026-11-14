module SafeBro
  # Every time someone unlocked sensitive data, with the reason they gave.
  class UnlocksController < ApplicationController
    PER_PAGE = SafeBro::ApplicationHelper::PER_PAGE

    def index
      @page = [ params[:page].to_i, 0 ].max
      @total = SensitiveAccess.count
      @unlocks = SensitiveAccess.includes(:session).order(started_at: :desc, id: :desc).limit(PER_PAGE).offset(@page * PER_PAGE)
      @command_counts = Command.where(sensitive_access_id: @unlocks.map(&:id)).group(:sensitive_access_id).count
      @open_total = SensitiveAccess.where(ended_at: nil).count
    end
  end
end
