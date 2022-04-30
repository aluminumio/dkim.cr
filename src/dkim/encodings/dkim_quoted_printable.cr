
module Dkim
  module Encodings
    # Implements DKIM-Quoted-Printable as described in rfc6376 section 2.11
    class DkimQuotedPrintable
      DkimUnafeChar = /[^\x21-\x3A\x3C\x3E-\x7E]/
      def encode(string : String)
        string.gsub(DkimUnafeChar) do |char|
          "=%.2x" % char[0].ord
          # "=%.2x" % char.unpack("C")
        end
      end
      def decode(string : String)
        string.gsub(/=([0-9A-F]{2})/) do
          $1.hex.chr
        end
      end
    end
  end
end
