require "openssl"

require "./body"
require "./dkim_header"
require "./header"
require "./canonicalized_headers"

require "dns"

module Dkim
  enum VerifyStatus
    Pass
    Fail
    BodyHashFail
    KeyRevoked
    Expired
    NoSignature
    NoKey
    InvalidSig
  end

  class VerifyMail
    @original_message : String
    @headers : Array(Header)
    @header_canonicalization : String
    @body_canonicalization : String
    @signing_algorithm : String
    property headers

    def initialize(message)
      message = message.to_s.gsub(/\r?\n/, "\r\n")
      headers, body = message.split(/\r?\n\r?\n/, 2)
      @original_message = message
      @headers = Header.parse headers
      @body    = Body.new body
      @signable_headers = [] of String
      @header_canonicalization = @body_canonicalization = ""
      @signing_algorithm = ""
    end

    def dkim_headers
      @headers.select do |h|
        h.key == "DKIM-Signature"
      end.map do |dh|
        TagValueList.parse(dh.value)
      end
    end

    def query_google_for_txt_record(dns_resolver, record)
      ask_packet = DNS::Packet.create_query_packet protocol_type: DNS::ProtocolType::UDP, name: record, record_type: DNS::Packet::RecordFlag::TXT, class_type: DNS::Packet::ClassFlag::Internet
      packets = dns_resolver.resolve host: record, record_type: DNS::Packet::RecordFlag::TXT, ask_packet: ask_packet

      if packets.empty?
        return nil
      else
        first_answers = packets[1]?.try(&.[0]?).try(&.answers)
        return nil unless first_answers
        ares = first_answers.select {|c| c.class == DNS::Records::TXT }[0]?
        return nil unless ares
        txt_record = ares.as(DNS::Records::TXT)
        return txt_record
      end
    end

    def verify(dns_server_ips : Array(String) = ["8.8.8.8", "4.2.2.2", "1.1.1.1"], public_key : String? = nil) : VerifyStatus
      results = verify_all(dns_server_ips, public_key)
      results.includes?(VerifyStatus::Pass) ? VerifyStatus::Pass : results.last
    end

    def verify_all(dns_server_ips : Array(String) = ["8.8.8.8", "4.2.2.2", "1.1.1.1"], public_key : String? = nil) : Array(VerifyStatus)
      dns_resolver = nil
      unless public_key
        dns_servers = Set(DNS::Address).new
        dns_server_ips.each do |dns_server_ip|
          dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new(dns_server_ip, 53_i32)
        end
        dns_resolver = DNS::Resolver.new dnsServers: dns_servers, options: DNS::Options.new
      end

      raw_dkim_headers = @headers.select { |h| h.key == "DKIM-Signature" }
      parsed_dkim_headers = raw_dkim_headers.map { |dh| TagValueList.parse(dh.value) }

      return [VerifyStatus::NoSignature] if parsed_dkim_headers.empty?

      results = [] of VerifyStatus
      parsed_dkim_headers.each_with_index do |dkh, i|
        results << verify_one(dkh, raw_dkim_headers[i], public_key, dns_resolver)
      end
      results
    end

    private def verify_one(dkh : TagValueList, raw_dkim : Header, public_key_b64 : String?, dns_resolver : DNS::Resolver?) : VerifyStatus
      # v= validation (RFC 6376 §3.5)
      return VerifyStatus::InvalidSig unless dkh["v"] == "1"

      # x= expiration check
      if expire_str = dkh["x"]
        return VerifyStatus::Expired if Time.unix(expire_str.to_i) < Time.utc
      end

      # Resolve public key
      key_b64 = public_key_b64
      unless key_b64
        dkim_domain = dkh["d"]
        selector = dkh["s"]
        return VerifyStatus::InvalidSig if dkim_domain.nil? || selector.nil?
        dkim_host = "#{selector}._domainkey.#{dkim_domain}"
        dkim_record = query_google_for_txt_record(dns_resolver.not_nil!, dkim_host)
        return VerifyStatus::NoKey if dkim_record.nil?
        dkim = TagValueList.parse(dkim_record.txt)
        key_b64 = dkim["p"]
      end

      return VerifyStatus::NoKey if key_b64.nil?
      return VerifyStatus::KeyRevoked if key_b64.empty?

      # Canonicalization defaults (RFC 6376 §3.5)
      @signing_algorithm = dkh["a"].as(String)
      c_tag = dkh["c"]
      if c_tag
        parts = c_tag.split("/")
        @header_canonicalization = parts[0]
        @body_canonicalization = parts[1]? || "simple"
      else
        @header_canonicalization = "simple"
        @body_canonicalization = "simple"
      end

      @signable_headers = dkh["h"].as(String).split(":").map(&.strip)

      # Body hash with l= support
      body = canonical_body
      if l_tag = dkh["l"]
        body = body.byte_slice(0, l_tag.to_i)
      end

      dkim_body_hash = dkh["bh"].as(String)
      signature = dkh["b"].as(String).gsub(/\s+/, "")

      message_body_hash = Base64.encode(String.new(digest_alg.update(body).final)).chomp
      return VerifyStatus::BodyHashFail if message_body_hash != dkim_body_hash

      # Verify signature
      headers = canonical_header
      canonical_dkim = raw_dkim.canonical(@header_canonicalization)
      final_headers = headers + canonical_dkim.sub(/\bb=[^;]*\z/, "b=")

      formatted_key = "-----BEGIN PUBLIC KEY-----\r\n#{key_b64}\r\n-----END PUBLIC KEY-----"
      rsa_key = OpenSSL::PKey::RSA.new(formatted_key)
      unencoded_signature = Base64.decode(signature)

      if rsa_key.verify(digest_alg, unencoded_signature, final_headers)
        VerifyStatus::Pass
      else
        VerifyStatus::Fail
      end
    end

    def canonicalized_headers
      CanonicalizedHeaders.new(@headers, @signable_headers)
    end

    def signed_headers
      @headers.map do |h|
        h.relaxed_key
      end.select do |key|
        @signable_headers.map do |hdr|
          hdr.downcase
        end.includes?(key)
      end
    end

    def canonical_header
      canonicalized_headers.canonical(@header_canonicalization)
    end

    def canonical_body
      @body.canonical(@body_canonicalization)
    end

    def digest_alg
      case @signing_algorithm
      when "rsa-sha1"
        OpenSSL::Digest.new("SHA1")
      when "rsa-sha256"
        OpenSSL::Digest.new("SHA256")
      else
        raise "Unknown digest algorithm: '#{@signing_algorithm}'"
      end
    end
  end
end
