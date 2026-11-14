require "test_helper"

class ValidatorTest < ActiveSupport::TestCase
  def validate(code, locked: true)
    SafeBro::Validator.new(SafeBro.config).validate(code, locked: locked)
  end

  def assert_forbidden(code, locked: true)
    assert_raises(SafeBro::ForbiddenCommand, "expected #{code.inspect} to be forbidden") { validate(code, locked: locked) }
  end

  test "ordinary commands pass" do
    assert_nothing_raised do
      validate "User.count"
      validate "Secretive.where(id: 1).first&.created_at"
      validate "module Foo; class Bar; def x = 1; end; end"
    end
  end

  test "reopening protected classes is forbidden" do
    assert_forbidden "class ActiveRecord::Base; def x; end; end"
    assert_forbidden "module ActiveRecord; end"
    assert_forbidden "class ApplicationRecord; end"
    assert_forbidden "class SafeBro::Session; end"
  end

  test "referencing SafeBro or IRB is always forbidden, even when unlocked" do
    assert_forbidden "SafeBro.config", locked: false
    assert_forbidden "::SafeBro::Session.delete_all", locked: false
    assert_forbidden "IRB.CurrentContext"
    assert_forbidden "ObjectSpace.each_object(Class)"
  end

  test "some constants are only forbidden while locked" do
    assert_forbidden "ActiveRecord::Encryption::Cipher"
    assert_forbidden "Open3.capture2('ls')"
    assert_nothing_raised { validate "ActiveRecord::Encryption::Cipher", locked: false }
  end

  test "ActiveRecord itself is fine to use" do
    assert_nothing_raised { validate "ActiveRecord::Base.connection.tables" }
  end

  test "forbidden methods are caught by name, in any form" do
    assert_forbidden "eval('1')"
    assert_forbidden "send(:eval, '1')"
    assert_forbidden "User.instance_eval { 1 }"
    assert_forbidden "User.class_eval { 1 }"
    assert_forbidden "system('ls')"
    assert_forbidden "exec 'ls'"
    assert_forbidden "`ls`"
    assert_forbidden "%x(ls)"
    assert_forbidden "IO.popen('ls')"
  end

  test "code that does not parse is still checked" do
    assert_forbidden "eval(("
    assert_forbidden "class SafeBro::"
  end

  test "suspicious terms are flagged, not blocked" do
    assert_raises(SafeBro::SuspiciousCommand) { validate "Rails.application.credentials.aws" }
    assert_raises(SafeBro::SuspiciousCommand) { validate "ENV['HOME']" }
  end

  test "forbidden wins over suspicious" do
    assert_forbidden "eval(ENV['X'])"
  end

  test "constant paths are read as written" do
    paths = SafeBro::ParsedCommand.new("ActiveRecord::Encryption::Config.new + Foo + ::Bar::Baz").constant_paths
    assert_equal %w[ ActiveRecord::Encryption::Config Foo Bar::Baz ], paths
  end
end
