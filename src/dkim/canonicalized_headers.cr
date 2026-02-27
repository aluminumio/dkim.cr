module Dkim
  class CanonicalizedHeaders
    include Enumerable(Dkim::Header)
    @signed_headers : Array(String)
    def initialize(@header_list : Array(Dkim::Header), signed_headers : Array(String))
      @signed_headers = signed_headers.map { |h| h.downcase }
    end
    def each(&block)
      header_hash = Hash(String,Array(Dkim::Header)).new
      @header_list.each do |header|
        header_hash[header.relaxed_key] ||= Array(Dkim::Header).new
        header_hash[header.relaxed_key] << header
      end

      @signed_headers.each do |key|
        if arr = header_hash[key]?
          if header = arr.pop?
            yield header
          end
        end
      end
    end
    def canonical(canonicalization)
      map do |header|
        "#{header.canonical(canonicalization)}\r\n"
      end.join
    end
  end
end
