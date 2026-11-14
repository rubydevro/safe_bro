module SafeBro
  # Schedule this (daily is plenty) to enforce config.retention.
  class PurgeJob < ActiveJob::Base
    queue_as :default

    def perform
      SafeBro::Session.purge!
    end
  end
end
