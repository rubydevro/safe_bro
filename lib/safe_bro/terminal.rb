module SafeBro
  # Talking to the person at the console.
  module Terminal
    COLORS = { green: 32, yellow: 33, red: 31, blue: 34 }.freeze

    class << self
      # Tests silence console output.
      attr_accessor :muted

      def interactive?
        $stdin.tty?
      end

      def say(message, color = nil)
        return if muted

        text = "\n#{message}\n"
        $stdout.puts(color && $stdout.tty? ? "\e[#{COLORS.fetch(color)}m#{text}\e[0m" : text)
      end

      # Something worth the person's attention, on stderr so it doesn't mix with output they pipe.
      def alert(message)
        $stderr.puts("SafeBro: #{message}") unless muted
      end

      # Asks until it gets a non-blank answer. Raises NotInteractive when there's nobody to ask.
      def ask(question)
        raise NotInteractive unless interactive?

        say(question, :green)
        answer = nil
        with_plain_output do
          loop do
            line = Reline.readline("> ", false)
            raise NotInteractive, "No answer given." if line.nil?

            answer = line.strip
            break unless answer.empty?
          end
        end
        answer
      end

      private
        # IRB colorizes what you type; the answer should look like plain text.
        def with_plain_output
          original = Reline.output_modifier_proc
          Reline.output_modifier_proc = nil
          yield
        ensure
          Reline.output_modifier_proc = original
        end
    end
  end
end
