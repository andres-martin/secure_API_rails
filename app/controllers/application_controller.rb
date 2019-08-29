class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  def basic_auth
    email = request.headers['X-User-Email']
    token = request.headers['X-Api-Token']
    user = User.find_by(email: email, api_token: token)
    head 401 unless user
  end
end