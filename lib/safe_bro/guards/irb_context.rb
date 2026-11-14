module SafeBro
  module Guards
    # Routes everything typed into IRB through the executor.
    module IrbContext
      # Printing the result of a command evaluates #inspect on it, which can read protected data.
      def inspect_last_value(...)
        SafeBro.executor.execute_in_protected_mode { super }
      end

      def evaluate(statement, ...)
        # irb passes an IRB::Statement; its #code is what was typed.
        code = statement.respond_to?(:code) ? statement.code : statement
        SafeBro.executor.execute(Array(code), console_path: safe_bro_console_path) { super }
      end

      private
        # The file name the evaluated code runs under.
        def safe_bro_console_path
          respond_to?(:eval_path) ? eval_path : irb_path
        end
    end
  end
end
