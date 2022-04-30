
require "./header"
require "./tag_value_list"
require "./encodings"

module Dkim
  class DkimHeader < Header
    def list; @list; end
    def initialize(@key : String = "DKIM-Signature", list : Hash(String, String) = Hash(String, String).new)
      @list = TagValueList.new list
      @value = ""
    end
    def value
      " " + @list.to_s
    end
    def [](k : String)
      encoder_for(k).decode(@list[k])
    end
    def []=(k : String, v : String)
      @list[k] = encoder_for(k).encode(v)
    end

    def encoder_for(key)
      case key
      when "v", "a", "c", "d", "h", "l", "q", "s", "t", "x" 
        Encodings::PlainText
      when "i", "z"
        Encodings::DkimQuotedPrintable
      when "b", "bh"
        Encodings::Base64
      else
        raise "unknown key: #{key}"
      end.new
    end
  end
end
