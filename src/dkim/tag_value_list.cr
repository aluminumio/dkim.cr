module Dkim
  class TagValueList
    @values : Hash(String, String)
    @keys   : Array(String)

    def initialize(values : Hash(String, String) = Hash(String, String).new)
      @keys = values.keys
      @values = values.dup
    end
    def to_s
      @keys.map do |k|
        "#{k}=#{@values[k]}"
      end.join("; ")
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
        key, value = keyval.split("=", 2)
        list[key.strip] = value.strip
      end
      list
    end
  end
end
