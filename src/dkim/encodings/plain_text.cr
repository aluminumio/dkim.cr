module Dkim
  module Encodings
    class PlainText
      def encode(v); v; end
      def decode(v); v; end
    end
  end
end
