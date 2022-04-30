require "./canonicalizable"

module Dkim
  class Body
    include Canonicalizable

    @body : String
    def body=(val); @body=val; end
    def body; @body; end

    def initialize(@body : String = "")
    end

    def canonical_relaxed
      # special case from errata 1377
      return "" if self.body.empty?

      body = self.body.dup

      # Reduces all sequences of WSP within a line to a single SP character.
      body = body.gsub(/[ \t]+/, " ")

      # Ignores all whitespace at the end of lines.  Implementations MUST NOT remove the CRLF at the end of the line.
      body = body.gsub(/ \r\n/, "\r\n")

      # Ignores all empty lines at the end of the message body.
      body = body.gsub(/[ \r\n]*\z/, "")

      body += "\r\n"
    end
    def canonical_simple
      body = self.body.dup

      # Ignores all empty lines at the end of the message body.
      body = body.gsub(/(\r?\n)*\z/, "")
      body += "\r\n"
    end
  end
end
