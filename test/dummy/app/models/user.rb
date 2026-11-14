# Stand-in for the host app's user model.
class User
  ROLES = %w[ staff auditor ].freeze

  attr_reader :role

  def self.for_role(role)
    new(role) if ROLES.include?(role)
  end

  def initialize(role)
    @role = role
  end

  def email
    "#{role}@example.com"
  end

  def can?(permission)
    permission == :audit && role == "auditor"
  end
end
