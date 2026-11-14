module SafeBro
  class Engine < ::Rails::Engine
    isolate_namespace SafeBro

    # The review UI is a section of the BroHub dashboard. Registered before routes are drawn,
    # so BroHub can mount this engine under <hub>/safe_bro.
    initializer "safe_bro.bro_hub" do
      BroHub.register :safe_bro,
        name: "SafeBro", label: "SafeBro · audit", accent: :red, order: 10,
        engine: "SafeBro::Engine",
        visible_to: ->(user) { SafeBro.config.can_audit.call(user) },
        items: [
          { label: "Sessions", path: "/", match: %r{\A/(sessions(/|\z)|\z)}, badge: -> { SafeBro::Session.review_pending.count } },
          { label: "Flagged commands", path: "/flagged" },
          { label: "Unlocks", path: "/unlocks" },
          { label: "Rules", path: "/rules" }
        ]
    end

    # Nothing is installed by merely loading the gem. Protections start with the console.
    console do
      SafeBro.supervisor.run_console if SafeBro.enabled?
    end

    runner do
      SafeBro.supervisor.run_runner if SafeBro.enabled? && SafeBro.config.audit_runner
    end

    rake_tasks do
      load File.expand_path("../tasks/safe_bro.rake", __dir__)
    end
  end
end
