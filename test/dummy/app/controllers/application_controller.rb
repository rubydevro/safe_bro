class ApplicationController < ActionController::Base
  helper_method :current_user

  private
    def current_user
      User.for_role(session[:role])
    end
end
