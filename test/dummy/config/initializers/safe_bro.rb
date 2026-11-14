SafeBro.configure do |config|
  # The dummy app runs in development/test, so switch it on explicitly where we want it.
  config.protected_environments = %w[ production development ]

  config.can_audit = ->(user) { user.can?(:audit) }
  config.freeze_internals = ENV["SAFE_BRO_E2E_FREEZE"].present?
  config.enabled = true if ENV["SAFE_BRO_E2E"]
  config.audit_runner = true if ENV["SAFE_BRO_E2E_RUNNER"]
end
