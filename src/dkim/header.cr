require "./canonicalizable"

module Dkim
  class Header
    include Canonicalizable

    property key,value
    def initialize(@key : String, @value : String)
    end
    def to_s(io : IO)
      io << key << ":" << value
    end

    def relaxed_key
      key = self.key.dup

      #Convert all header field names (not the header field values) to lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".
      key = key.downcase

      # Delete any WSP characters remaining before the colon separating the header field name from the header field value.
      key = key.gsub(/[ \t]*\z/, "")

      key
    end
    def relaxed_value
      value  = self.value.dup

      # Unfold all header field continuation lines as described in [RFC2822]
      value = value.gsub(/\r?\n[ \t]+/, " ")

      # Convert all sequences of one or more WSP characters to a single SP character.
      value = value.gsub(/[ \t]+/, " ")

      # Delete all WSP characters at the end of each unfolded header field value.
      value = value.gsub(/[ \t]*\z/, "")
      
      # Delete any WSP characters remaining after the colon separating the header field name from the header field value.
      value = value.gsub(/\A[ \t]*/, "")

      value
    end
    def canonical_relaxed
      "#{relaxed_key}:#{relaxed_value}"
    end
    def canonical_simple
      "#{key}:#{value}"
    end

    def self.parse(header_string)
      header_string.split(/\r?\n(?!([ \t]))/).map do |header|
        key, value = header.split(":", 2)
        new(key, value)
      end
    end
  end
end
