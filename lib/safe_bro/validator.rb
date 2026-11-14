module SafeBro
  # Static analysis of a console command, before it runs. Each validation raises
  # ForbiddenCommand (blocked) or SuspiciousCommand (runs, but is flagged).
  #
  # This is a speed bump for honest mistakes and a tripwire for dishonest attempts. It is not
  # a sandbox: Ruby is too dynamic for that. The runtime guards (see Guards) cover the most
  # obvious ways around it, and the rest is what the audit trail is for.
  class Validator
    class Validation
      def initialize(config)
        @config = config
      end

      attr_reader :config
    end

    # class Foo / module Foo for a protected Foo or Foo::Bar.
    class ForbiddenReopening < Validation
      def validate(command, locked:)
        command.reopened_constants.each do |name|
          if config.forbidden_reopening.any? { |forbidden| name == forbidden || name.start_with?("#{forbidden}::") }
            raise ForbiddenCommand, "Reopening #{name} is not allowed."
          end
        end
      end
    end

    class ForbiddenConstantReference < Validation
      def validate(command, locked:)
        forbidden = config.forbidden_constants.fetch(:always, [])
        forbidden += config.forbidden_constants.fetch(:locked, []) if locked
        command.constant_paths.each do |path|
          match = forbidden.find { |f| path == f || path.start_with?("#{f}::") }
          raise ForbiddenCommand, "Referencing #{match} is not allowed#{' while locked' unless config.forbidden_constants.fetch(:always, []).include?(match)}." if match
        end
      end
    end

    # Method names from forbidden_methods ("Kernel#eval" -> eval), wherever they appear.
    class ForbiddenMethods < Validation
      def validate(command, locked:)
        names = config.forbidden_methods.map { |entry| entry.split(/[#.]/, 2).last }.uniq
        used = command.method_names & names
        raise ForbiddenCommand, "Calling #{used.first} is not allowed." if used.any?
      end
    end

    class SuspiciousTerms < Validation
      def validate(command, locked:)
        term = config.suspicious_terms.find { |t| command.source.include?(t) }
        raise SuspiciousCommand, "Command mentions #{term}." if term
      end
    end

    VALIDATIONS = [ ForbiddenReopening, ForbiddenConstantReference, ForbiddenMethods, SuspiciousTerms ].freeze

    def initialize(config = SafeBro.config)
      @validations = VALIDATIONS.map { |klass| klass.new(config) }
    end

    # Raises on the first failing validation. Forbidden beats suspicious, so run every
    # validation and only then raise a suspicion.
    def validate(source, locked: true)
      command = ParsedCommand.new(source)
      suspicion = nil
      @validations.each do |validation|
        validation.validate(command, locked: locked)
      rescue SuspiciousCommand => error
        suspicion ||= error
      end
      raise suspicion if suspicion
    end
  end
end
