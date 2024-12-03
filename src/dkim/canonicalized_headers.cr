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
        if header = header_hash[key].pop
          yield header
        end
      end
    end
    def canonical(canonicalization)
      map do |header|
        header.to_s(canonicalization) + "\r\n"
      end.join
    end
  end
end
