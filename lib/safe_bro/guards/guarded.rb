module SafeBro
  module Guards
    # Builds and prepends a module that makes the given methods raise ProtectedResource when
    # they are called straight from the console while the resource is locked. Library code
    # calling the same methods is unaffected.
    module Guarded
      class << self
        # condition: ->(receiver, args) { true } narrows which calls are guarded.
        # inherited: names to guard even though the owner doesn't define them itself (the guard
        # then sits in front of the inherited method).
        def install(target, methods, resource, condition: nil, scope: :instance, inherited: [])
          owner = scope == :singleton ? target.singleton_class : target
          guard_module = Module.new
          guarded = 0

          Array(methods).each do |name|
            visibility = visibility_of(owner, name) || (:public if inherited.include?(name)) or next
            guard_module.define_method(name) do |*args, **kwargs, &block|
              if SafeBro.executor.executing_user_command? && (condition.nil? || condition.call(self, args))
                SafeBro.guard!(resource, "(#{name})", locations: caller_locations(1, 1))
              end
              super(*args, **kwargs, &block)
            end
            guard_module.send(visibility, name)
            guarded += 1
          end

          owner.prepend(guard_module) if guarded > 0
          guard_module
        end

        private
          # Only methods the owner itself defines, so subclasses aren't guarded twice.
          def visibility_of(owner, name)
            if owner.public_instance_methods(false).include?(name) then :public
            elsif owner.protected_instance_methods(false).include?(name) then :protected
            elsif owner.private_instance_methods(false).include?(name) then :private
            end
          end
      end
    end
  end
end
