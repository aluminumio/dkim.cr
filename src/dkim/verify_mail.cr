require "openssl"

require "./body"
require "./dkim_header"
require "./header"
require "./canonicalized_headers"

require "dns"

module Dkim
  class VerifyMail
    @original_message : String
    @headers : Array(Header)
    @header_canonicalization : String
    @body_canonicalization : String
    @domain : String
    @selector : String
    @identity : String?
    @query_method : String?
    @time   : Time?
    @expire : Time?
    @signing_algorithm : String
    property headers

    # A new instance of VerifyMail
    #
    # @param [String,#to_s] message mail message to be signed
    # @param [Hash] options hash of options for signing. Defaults are taken from {Dkim}. See {Options} for details.
    def initialize(message)
      message = message.to_s.gsub(/\r?\n/, "\r\n")
      headers, body = message.split(/\r?\n\r?\n/, 2)
      @original_message = message
      @headers = Header.parse headers
      @body    = Body.new body
      @signable_headers = [] of String
      @header_canonicalization = @body_canonicalization = ""
      @signing_algorithm = @domain = @selector = ""
    end

    def dkim_headers
      @headers.select do |h|
        h.key == "DKIM-Signature" 
      end.map do |dh|
        TagValueList.parse(dh.value)
      end
    end

    def query_google_for_txt_record(dns_resolver, record)
      # puts "Resolving TXT for: #{record}"
      #before = Time.local
      ask_packet = DNS::Packet.create_getaddrinfo_ask protocol_type: DNS::ProtocolType::UDP, name: record, record_type: DNS::Packet::RecordFlag::TXT, class_type: DNS::Packet::ClassFlag::Internet
      packets = dns_resolver.resolve host: record, record_type: DNS::Packet::RecordFlag::TXT, ask_packet: ask_packet
      #after = Time.local
      #delta = after-before
      #puts "Timing: #{delta}"

      first_answers = packets[1][0].answers
      ares = first_answers.select {|c| c.class == DNS::Records::TXT }[0]
      return nil unless ares # Can have none...
      txt_record = ares.as(DNS::Records::TXT)
      return txt_record
    end

    def verify(dns_server_ips : Array(String) = ["8.8.8.8", "4.2.2.2", "1.1.1.1"])
      dns_servers = Set(DNS::Address).new
      dns_server_ips.each do |dns_server_ip|
        dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new(dns_server_ip, 53_i32)
      end
      dns_resolver = DNS::Resolver.new dnsServers: dns_servers, options: DNS::Options.new

      sender= @headers.select { |h| h.key == "Sender" }
      from  = @headers.select { |h| h.key == "From" }
      if !sender.any? && !from.any?
        puts "Message does not have a Sender nor From so DKIM source cannot be verified."
      end
      sender_domain = ((sender.any? && sender.first) || from.first).to_s.split("<").last.split(">").first.split("@").last
      dkh = self.dkim_headers.first
      # puts "DKIM Header:\n#{dkh.to_s}"
      if dkh.nil?
        puts "No DKIM header found."
        return false
      end

      time_as_string =  dkh["t"]
      @query_method = dkh["q"]
      @time     = Time.unix(time_as_string.to_i) unless time_as_string.nil?
      dkim_domain   = dkh["d"]
      @domain = dkim_domain unless dkim_domain.nil?
      selector = dkh["s"]
      @selector = selector unless selector.nil?
      dkim_host = "#{@selector}._domainkey.#{dkim_domain}"
      dkim_record = query_google_for_txt_record(dns_resolver, dkim_host)
      if dkim_record.nil?
        puts "No valid DKIM Record found for #{dkim_host}."
        return false
      end
      dkim_record_txt = dkim_record.txt
      dkim = TagValueList.parse(dkim_record_txt)
      dkim_public_key = dkim["p"]
      if dkim["v"] != "DKIM1" || dkim["k"] != "rsa"
        puts "Nonstandard DKIM keys: #{dkim.to_s}"
      end
      if dkim_domain != sender_domain
        puts "DKIM Verification Warning: Sending host: '#{dkim_domain}' but the mail appears to be from the host '#{sender_domain}'. If you trust #{dkim_domain} then you may trust the email, but #{dkim_domain} is not necessarily proof #{sender_domain} authorized the email."
      end
      identity = dkh["i"]
      @identity = identity unless identity.nil?
      expire   = dkh["x"]
      @signing_algorithm = dkh["a"].as(String)
      if dkh["c"]
        @header_canonicalization, @body_canonicalization = dkh["c"].as(String).split("/")
      end

      dkim_body_hash = dkh["bh"].as(String)
      signature      = dkh["b"].as(String).gsub(/\r\n */, "")

      @signable_headers = dkh["h"].as(String).split(":")

      formatted_key = "-----BEGIN PUBLIC KEY-----\r\n#{dkim_public_key}\r\n-----END PUBLIC KEY-----"
      public_key = OpenSSL::PKey::RSA.new(formatted_key)

      headers = canonical_header
      headers += dkim_header.to_s(@header_canonicalization)

      message_body_hash = Base64.encode(String.new(digest_alg.update(canonical_body).final)).chomp
      if message_body_hash != dkim_body_hash
        puts "WARNING!!! Message body does not match DKIM verification."
        # TODO: Support [the 'l' tag](https://www.rfc-editor.org/rfc/rfc6376#section-3.7), but would help to have a message / test beforehand
        return false
      end
      
      # puts headers
      # TODO: Stop using dkh and use our generated canonical headers instead.
      final_headers = headers.split("dkim-signature:").first + "dkim-signature:" + dkh.to_s.split("b=").first + "b="
      # puts final_headers
      # final_hash = digest_alg.update(final_headers).final
      # puts final_hash.hexstring
      unencoded_signature = Base64.decode(signature.gsub(/\r\n */, ""))
      # puts unencoded_signature.hexstring
      public_key.verify(digest_alg, unencoded_signature, final_headers)
    end

    # @return [DkimHeader] Constructed signature for the mail message
    def dkim_header : DkimHeader
      dkim_header = DkimHeader.new

      raise "A domain is required"      unless @domain
      raise "A selector is required"    unless @selector

      # Add basic DKIM info
      dkim_header["v"] = "1"
      dkim_header["a"] = @signing_algorithm
      dkim_header["c"] = "#{@header_canonicalization}/#{@body_canonicalization}"
      dkim_header["d"] = @domain
      dkim_header["i"] = @identity || @domain
      dkim_header["q"] = @query_method.as(String)        unless @query_method.nil?
      dkim_header["s"] = @selector
      dkim_header["t"] = @time.as(Time).to_unix.to_s unless @time.nil?
      dkim_header["x"] = @expire.as(Time).to_unix.to_s unless @expire.nil?

      # Add body hash and blank signature
      dkim_header["bh"]= String.new(digest_alg.update(canonical_body).final)
      # dkim_header["bh"]= digest_alg.digest(canonical_body)
      dkim_header["h"] = signed_headers.join(":")
      dkim_header["b"] = ""

      # Calculate signature based on intermediate signature header
      headers = canonical_header
      headers += dkim_header.to_s(@header_canonicalization)

      dkim_header
    end

    # @return [String] Message combined with calculated dkim header signature
    def to_s
      dkim_header.to_s + "\r\n" + @original_message
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


