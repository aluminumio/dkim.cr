require "openssl"
require "openssl_ext"

require "./dkim/signed_mail"
require "./dkim/verify_mail"

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
end
