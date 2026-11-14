require "ripper"

module SafeBro
  # A lenient lexical view of a console command. It uses Ripper's tokenizer, which keeps
  # producing tokens for code that doesn't parse, so a syntax trick can't hide a constant
  # or method name from the validations.
  class ParsedCommand
    attr_reader :source

    def initialize(source)
      @source = Array(source).join("\n")
    end

    def tokens
      @tokens ||= Ripper.lex(source).map { |(_pos, type, text, _state)| [ type, text ] }
    end

    # Constant paths as written: "ActiveRecord::Encryption::Config" (leading :: dropped).
    def constant_paths
      @constant_paths ||= begin
        paths = []
        significant = tokens.reject { |type, _| type == :on_sp || type == :on_ignored_nl || type == :on_nl }
        significant.each_with_index do |(type, text), i|
          next unless type == :on_const

          previous = significant[i - 1]
          after_scope = i > 0 && previous == [ :on_op, "::" ]
          qualified = after_scope && i > 1 && significant[i - 2][0] == :on_const
          if qualified && paths.any?
            paths[-1] = "#{paths.last}::#{text}"
          else
            paths << text
          end
        end
        paths
      end
    end

    # Names after `class`/`module`: the things this command (re)opens.
    def reopened_constants
      @reopened_constants ||= begin
        significant = tokens.reject { |type, _| type == :on_sp }
        significant.each_with_index.filter_map do |(type, text), i|
          next unless type == :on_kw && %w[ class module ].include?(text)

          name = +""
          significant[(i + 1)..].each do |t, x|
            break unless t == :on_const || (t == :on_op && x == "::")
            name << x
          end
          name.delete_prefix("::").presence
        end
      end
    end

    # Identifiers that might be method calls, plus backtick/%x shell execution as "`".
    def method_names
      @method_names ||= tokens.filter_map do |type, text|
        case type
        when :on_ident, :on_const, :on_kw then text
        when :on_backtick then "`"
        end
      end.uniq
    end
  end
end
