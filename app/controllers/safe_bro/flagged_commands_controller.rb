module SafeBro
  # Every command that was blocked or flagged, newest first.
  class FlaggedCommandsController < ApplicationController
    PER_PAGE = SafeBro::ApplicationHelper::PER_PAGE

    def index
      @page = [ params[:page].to_i, 0 ].max
      scope = Command.flagged
      @total = scope.count
      @commands = scope.includes(:session).order(created_at: :desc, id: :desc).limit(PER_PAGE).offset(@page * PER_PAGE)
      @blocked_total = Command.blocked.count
    end
  end
end
