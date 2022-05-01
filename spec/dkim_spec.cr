require "./spec_helper"

require "spec"
require "../src/dkim"

describe Dkim do
  describe "signing with defaults" do
    it "can sign an email with default settings" do
      signed_mail =  Dkim::SignedMail.new(MAIL,
                                  time: Time.unix(TIME),
                                  domain: DOMAIN,
                                  private_key: KEY,
                                  selector: SELECTOR)
      dkim_header = signed_mail.dkim_header.list
      ("rsa-sha256" == dkim_header["a"]).should be_true
      ("brisbane" == dkim_header["s"]).should be_true
      ("example.com" == dkim_header["d"]).should be_true
      ("relaxed/relaxed" == dkim_header["c"]).should be_true
      ("dns/txt" == dkim_header["q"]).should be_true
      ("from:to:subject:date:message-id" == dkim_header["h"]).should be_true

      ("2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=" == dkim_header["bh"]).should be_true
      ("dQOeSpGJTfSbX4hPGGsy4ipcNAzC/33K7XaEXkjBneJJhv6MczHkJNsfmXeYESNIh5WVTuvE5IbnDPBVFrL+b3GKiLiyp/vlKO2NJViX4dLnKT/GdxjJh06ljZcYjUA+PorHvMwdu+cDsCffN8A7IhfVdsFruQr3vFPD0JyJ9XU=" == dkim_header["b"]).should be_true
    end
  end
end
