require "test_helper"

class ClientIpTest < ActiveSupport::TestCase
  def with_env(vars)
    old = vars.keys.to_h { |k| [ k, ENV[k] ] }
    vars.each { |k, v| ENV[k] = v }
    yield
  ensure
    old.each { |k, v| ENV[k] = v }
  end

  def ip = SafeBro::Supervisor.new.current_client_ip

  test "prefers CONSOLE_CLIENT_IP, then SSH_CLIENT, then SSH_CONNECTION" do
    with_env("CONSOLE_CLIENT_IP" => "203.0.113.7", "SSH_CLIENT" => "198.51.100.1 5000 22", "SSH_CONNECTION" => nil) { assert_equal "203.0.113.7", ip }
    with_env("CONSOLE_CLIENT_IP" => nil, "SSH_CLIENT" => "198.51.100.1 5000 22", "SSH_CONNECTION" => nil) { assert_equal "198.51.100.1", ip }
    with_env("CONSOLE_CLIENT_IP" => nil, "SSH_CLIENT" => nil, "SSH_CONNECTION" => "2001:db8::1 5000 2001:db8::2 22") { assert_equal "2001:db8::1", ip }
  end

  test "ignores values that are not an IP address" do
    with_env("CONSOLE_CLIENT_IP" => "<script>alert(1)</script>", "SSH_CLIENT" => nil, "SSH_CONNECTION" => nil) { assert_nil ip }
  end

  test "is nil when nothing is known" do
    with_env("CONSOLE_CLIENT_IP" => nil, "SSH_CLIENT" => nil, "SSH_CONNECTION" => nil) { assert_nil ip }
  end

  test "the session stores it" do
    SafeBro.recorder.start_session(username: "alice", reason: "x", client_ip: "203.0.113.7")
    assert_equal "203.0.113.7", SafeBro::Session.last.client_ip
  ensure
    SafeBro.recorder.finish_session
  end
end
