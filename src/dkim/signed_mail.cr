require "openssl"

require "./body"
require "./dkim_header"
require "./header"
require "./canonicalized_headers"

module Dkim
  class SignedMail
    @private_key : OpenSSL::PKey::RSA?
    def private_key; @private_key; end
    def private_key=(key : OpenSSL::PKey::RSA | String)
      key = OpenSSL::PKey::RSA.new(key) if key.is_a?(String)
      @private_key = key
    end

    @original_message : String
    @headers : Array(Header)
    property headers

    # A new instance of SignedMail
    #
    # @param [String,#to_s] message mail message to be signed
    # @param [Hash] options hash of options for signing. Defaults are taken from {Dkim}. See {Options} for details.
    def initialize(message,
        @time : Time = Time.utc,
        @domain : String = "example.com",
        private_key : String | OpenSSL::PKey::RSA | Nil = nil,
        @selector : String = "dkim",
        @identity : String? = nil,
        @expire : Time? = nil,
        @signing_algorithm : String = "rsa-sha256",
        @header_canonicalization : String = "relaxed", 
        @body_canonicalization   : String = "relaxed",
        @signable_headers : Array(String) = Dkim::DefaultHeaders)

      message = message.to_s.gsub(/\r?\n/, "\r\n")
      headers, body = message.split(/\r?\n\r?\n/, 2)
      @original_message = message
      @headers = Header.parse headers
      @body    = Body.new body
      self.private_key = private_key unless private_key.nil?
    end

    def canonicalized_headers
      CanonicalizedHeaders.new(@headers, signed_headers)
    end

    # @return [Array<String>] lowercased names of headers in the order they are signed
    def signed_headers
      @headers.map do |h| 
        h.relaxed_key
      end.select do |key|
        @signable_headers.map do |hdr|
          hdr.downcase
        end.includes?(key)
      end
    end

    # @return [String] Signed headers of message in their canonical forms
    def canonical_header
      canonicalized_headers.to_s(@header_canonicalization)
    end

    # @return [String] Body of message in its canonical form
    def canonical_body
      @body.to_s(@body_canonicalization)
    end

    # @return [DkimHeader] Constructed signature for the mail message
    def dkim_header : DkimHeader
      dkim_header = DkimHeader.new

      raise "A private key is required" unless private_key
      raise "A domain is required"      unless @domain
      raise "A selector is required"    unless @selector

      # Add basic DKIM info
      dkim_header["v"] = "1"
      dkim_header["a"] = @signing_algorithm
      dkim_header["c"] = "#{@header_canonicalization}/#{@body_canonicalization}"
      dkim_header["d"] = @domain
      dkim_header["i"] = @identity.as(String) unless @identity.nil?
      dkim_header["q"] = "dns/txt"
      dkim_header["s"] = @selector
      dkim_header["t"] = @time.to_unix.to_s
      dkim_header["x"] = @expire.as(Time).to_unix.to_s unless @expire.nil?

      # Add body hash and blank signature
      dkim_header["bh"]= String.new(digest_alg.update(canonical_body).final)
      # dkim_header["bh"]= digest_alg.digest(canonical_body)
      dkim_header["h"] = signed_headers.join(":")
      dkim_header["b"] = ""

      # Calculate signature based on intermediate signature header
      headers = canonical_header
      # puts "dkim_header.class: #{dkim_header.class}\n"
      # puts "header_canonicalization: #{header_canonicalization}\n"
      headers += dkim_header.to_s(@header_canonicalization)
      dkim_header["b"] = String.new(private_key.as(OpenSSL::PKey::RSA).sign(digest_alg, headers))

      dkim_header
    end

    # @return [String] Message combined with calculated dkim header signature
    def to_s
      dkim_header.to_s + "\r\n" + @original_message
    end

    # private
    def digest_alg
      case @signing_algorithm
      when "rsa-sha1"
        OpenSSL::Digest.new("SHA1")
        # OpenSSL::Digest::SHA1.new
      when "rsa-sha256"
        OpenSSL::Digest.new("SHA256")
        # OpenSSL::Digest::SHA256.new
      else
        raise "Unknown digest algorithm: '#{@signing_algorithm}'"
      end
    end
  end
end

