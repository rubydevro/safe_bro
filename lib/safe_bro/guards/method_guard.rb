module SafeBro
  module Guards
    # Runtime backstop for config.forbidden_methods. The validator catches `eval(...)` written
    # out, this catches `send(:eval, ...)`, `method(:eval).call`, and friends.
    module MethodGuard
      def self.install
        SafeBro.config.forbidden_methods.each do |entry|
          owner_name, separator, method_name = entry.partition(/[#.]/)
          owner = owner_name.safe_constantize or next
          scope = separator == "." ? :singleton : :instance
          install_one(owner, method_name.to_sym, scope, entry)
        end
      end

      def self.install_one(target, name, scope, entry)
        owner = scope == :singleton ? target.singleton_class : target
        visibility = %i[ public protected private ].find { |v| owner.send(:"#{v}_instance_methods", false).include?(name) } or return

        guard = Module.new
        guard.define_method(name) do |*args, **kwargs, &block|
          if SafeBro.executor.executing_user_command? && SafeBro.executor.from_console?(caller_locations(1, 1))
            raise ForbiddenCommand, "Calling #{entry} is not allowed."
          end
          super(*args, **kwargs, &block)
        end
        guard.send(visibility, name)
        owner.prepend(guard)
      end
    end
  end
end
