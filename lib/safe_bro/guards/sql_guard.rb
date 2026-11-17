module SafeBro
  module Guards
    # Every statement ActiveRecord runs goes through the adapter's #log. A command that
    # mentions SafeBro's tables (or BroHub's audit table) (to read, change or delete the audit trail) is stopped here.
    module SqlGuard
      # The audit table every Bro gem shares holds SafeBro's key moments too.
      TABLES = /safe_bro_(sessions|sensitive_accesses|commands|audits)|bro_hub_audit_events/i

      private
        def log(sql, *args, **kwargs, &block)
          if SafeBro.executor.executing_user_command? && sql.to_s.match?(TABLES)
            raise TamperingAttempt, "The audit trail can't be touched from the console."
          end

          super
        end
    end
  end
end
