namespace :safe_bro do
  desc "Delete console sessions older than config.retention (flagged ones are kept unless keep_flagged is off)"
  task purge: :environment do
    deleted = SafeBro::Session.purge!
    puts "SafeBro: purged #{deleted} session#{'s' unless deleted == 1}"
  end
end
