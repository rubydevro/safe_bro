module SafeBro
  class AuditsController < ApplicationController
    def create
      session = Session.find(params[:session_id])
      if !SafeBro.config.allow_self_audit && safe_bro_user_label.to_s == session.username
        return redirect_to session_path(session), alert: "You can't audit your own session."
      end

      audit = session.audits.new(audit_params.merge(auditor: safe_bro_user_label))
      if audit.save
        redirect_to next_path_after(session), notice: "Session ##{session.id} #{audit.status}."
      else
        redirect_to session_path(session, filter_params), alert: audit.errors.full_messages.to_sentence
      end
    end

    private
      def audit_params
        params.require(:audit).permit(:status, :notes)
      end

      def filter_params
        params.permit(:attention, :username, :from, :to).to_h.symbolize_keys.merge(status: params[:filter_status]).compact_blank
      end

      # After deciding, move on to the next session still waiting, within the same filter.
      def next_path_after(session)
        scope = Session.review_pending.where.not(id: session.id)
        scope = scope.needing_attention if params[:attention] == "1"
        scope = scope.where(username: params[:username]) if params[:username].present?
        following = scope.chronological.first
        following ? session_path(following, filter_params) : root_path(status: params[:filter_status].presence || "pending")
      end
  end
end
