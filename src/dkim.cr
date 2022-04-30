require "openssl"
require "openssl_ext"

require "./dkim/signed_mail"

module Dkim
  DefaultHeaders = %w{
    From Sender Reply-To Subject Date
    Message-ID To Cc MIME-Version
    Content-Type Content-Transfer-Encoding Content-ID Content-Description
    Resent-Date Resent-From Resent-Sender Resent-To Resent-cc
    Resent-Message-ID
    In-Reply-To References
    List-Id List-Help List-Unsubscribe List-Subscribe
    List-Post List-Owner List-Archive}

  @@signable_headers : Array(String)?
  def self.signable_headers=(val); @@signable_headers=val; end
  @@domain : String?
  def self.domain=(val); @@domain=val; end
  def self.domain; @@domain; end
  @@identity : String?
  def self.identity=(val); @@identity=val; end
  @@selector : String?
  def self.selector=(val); @@selector=val; end
  def self.selector; @@selector; end
  @@signing_algorithm : String?
  def self.signing_algorithm=(val); @@signing_algorithm=val; end
  @@private_key : OpenSSL::PKey::RSA?
  def self.private_key=(key)
    key = OpenSSL::PKey::RSA.new(key) if key.is_a?(String)
    @@private_key = key
  end
  def self.private_key; @@private_key; end
  @@header_canonicalization : String?
  def self.header_canonicalization=(val); @@header_canonicalization=val; end
  @@body_canonicalization : String?
  def self.body_canonicalization=(val); @@body_canonicalization=val; end

  def self.sign(message : String)
    SignedMail.new(message).to_s
  end
end

Dkim.signable_headers        = Dkim::DefaultHeaders.dup
Dkim.domain                  = nil
Dkim.identity                = nil
Dkim.selector                = nil
Dkim.signing_algorithm       = "rsa-sha256"
Dkim.private_key             = nil
Dkim.header_canonicalization = "relaxed"
Dkim.body_canonicalization   = "relaxed"

