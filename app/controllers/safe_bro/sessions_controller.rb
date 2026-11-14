module SafeBro
  class SessionsController < ApplicationController
    PER_PAGE = SafeBro::ApplicationHelper::PER_PAGE
    STATUSES = %w[ pending approved flagged ].freeze

    helper_method :filter_params

    def index
      @filter = filter_params
      @sessions = filtered_sessions.chronological.limit(PER_PAGE).offset(page * PER_PAGE)
      @total = filtered_sessions.count
      @page = page
      load_counts
    end

    def show
      @session = Session.find(params[:id])
      @commands = @session.commands.includes(:sensitive_access).chronological
      @audits = @session.audits.order(:id)
      @can_audit_this = can_audit?(@session)
      @next_session = filtered_sessions.review_pending.where.not(id: @session.id).chronological.first
    end

    private
      # One query each, instead of two per row, plus the totals for the page heading.
      def load_counts
        ids = @sessions.map(&:id)
        @unlock_counts = SensitiveAccess.where(session_id: ids).group(:session_id).count
        @flag_counts = Command.flagged.where(session_id: ids).group(:session_id).count
        matching = filtered_sessions.select(:id)
        @unlock_total = SensitiveAccess.where(session_id: matching).count
        @flag_total = Command.flagged.where(session_id: matching).count
      end

      def filtered_sessions
        scope = Session.all
        scope = scope.where(review_status: filter_params[:status]) if STATUSES.include?(filter_params[:status])
        scope = scope.needing_attention if filter_params[:attention] == "1"
        scope = scope.where(username: filter_params[:username]) if filter_params[:username].present?
        scope = scope.on_or_after(parse_date(filter_params[:from]).beginning_of_day) if parse_date(filter_params[:from])
        scope = scope.before(parse_date(filter_params[:to]).end_of_day) if parse_date(filter_params[:to])
        scope
      end

      def filter_params
        @filter_params ||= begin
          permitted = params.permit(:status, :attention, :username, :from, :to).to_h.symbolize_keys
          permitted[:status] = "pending" unless params.key?(:status)
          permitted.compact_blank
        end
      end

      def page
        [ params[:page].to_i, 0 ].max
      end

      def parse_date(value)
        Date.iso8601(value.to_s) if value.present?
      rescue ArgumentError
        nil
      end

      def can_audit?(session)
        SafeBro.config.allow_self_audit || safe_bro_user_label.to_s != session.username
      end
  end
end
