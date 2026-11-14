require_relative "lib/safe_bro/version"

Gem::Specification.new do |spec|
  spec.name        = "safe_bro"
  spec.version     = SafeBro::VERSION
  spec.authors     = [ "Ruby Dev SRL" ]
  spec.email       = [ "office@rubydev.ro" ]
  spec.summary     = "Audited, guarded Rails console access, with a built-in review UI."
  spec.description = "Records Rails console sessions (who, why, what), asks for a justification before sensitive " \
                     "data is touched, blocks tampering and risky methods, and ships a mountable engine where " \
                     "auditors review sessions. One gem instead of console1984 plus audits1984."
  spec.homepage    = "https://www.rubydev.ro"
  spec.license     = "MIT"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["rubygems_mfa_required"] = "true"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/rubydevro/safe_bro"
  spec.metadata["bug_tracker_uri"] = "https://github.com/rubydevro/safe_bro/issues"

  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    Dir["{app,config,db,lib}/**/*", "MIT-LICENSE", "Rakefile", "README.md"]
  end

  spec.required_ruby_version = ">= 3.2"
  spec.add_dependency "rails", ">= 7.1"
  # Console commands (unlock!/lock!) use the IRB::Command API introduced in irb 1.13.
  spec.add_dependency "irb", ">= 1.13"
  # The review UI lives inside BroHub's shared shell.
  spec.add_dependency "bro_hub", ">= 0.1.1"
end
