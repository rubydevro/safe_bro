class AddClientIpToSafeBroSessions < ActiveRecord::Migration[7.1]
  def change
    add_column :safe_bro_sessions, :client_ip, :string
  end
end
