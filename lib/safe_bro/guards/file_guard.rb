require "pathname"
require "fileutils"

module SafeBro
  module Guards
    # Files that hold secrets (master.key, .env) can't be read from the console while locked.
    module FileGuard
      def self.protected_path?(path)
        return false unless path.respond_to?(:to_path) || path.is_a?(String)

        expanded = File.expand_path(path.respond_to?(:to_path) ? path.to_path : path)
        SafeBro.config.protected_file_patterns.any? { |pattern| pattern.match?(expanded) }
      rescue ArgumentError, TypeError
        false
      end

      def self.install
        by_path = ->(_receiver, args) { protected_path?(args.first) }
        Guarded.install(IO, %i[ read binread readlines foreach ], :files, condition: by_path, scope: :singleton)
        Guarded.install(File, %i[ new open ], :files, condition: by_path, scope: :singleton, inherited: %i[ new open ])
        copying = ->(_receiver, args) { Array(args.first).any? { |path| protected_path?(path) } }
        Guarded.install(FileUtils, %i[ cp copy copy_file cp_r mv move install ], :files, condition: copying, scope: :singleton)
        Guarded.install(Kernel, %i[ open ], :files, condition: by_path)
        Guarded.install(Pathname, %i[ read binread readlines ], :files, condition: ->(receiver, _) { protected_path?(receiver) })
      end
    end
  end
end
