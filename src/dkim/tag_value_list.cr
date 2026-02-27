module Dkim
  class TagValueList
    @values : Hash(String, String)
    property keys
    @keys   : Array(String)

    def initialize(values : Hash(String, String) = Hash(String, String).new)
      @keys = values.keys
      @values = values.dup
    end
    def list
      @keys.map do |k|
        "#{k}=#{@values[k]}"
      end.join("; ")
    end
    def to_s(io : IO)
      io << list
    end
    def [](k)
      @values[k]?
    end
    def []=(k : String, v : String)
      @keys << k unless self[k]
      @values[k] = v
    end
    def self.parse(string)
      list = new
      string.split(";").each do |keyval|
        next unless keyval.includes?('=')
        key, value = keyval.split("=", 2)
        list[key.strip] = value.strip
      end
      list
    end
  end
end
