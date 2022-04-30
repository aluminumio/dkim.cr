
if ARGV.size != 3 && ARGV.size != 4
  puts "Usage: dkimsign DOMAIN SELECTOR KEYFILE [MAILFILE]"
  exit 0
end

require "./dkim"

domain, selector, keyfile, mailfile = ARGV

key  = File.read(keyfile)
mail = mailfile ? File.read(mailfile) : STDIN.gets_to_end
if mail
  mail = mail.gsub(/\r?\n/, "\r\n")
end

Dkim.domain = domain
Dkim.selector = selector
Dkim.private_key = key

dkim_mail =  Dkim::SignedMail.new(mail)
# print "Dkim vars not getting set in signedmail object." unless dkim_mail.private_key
# TODO: Stop doing this by hand, since it should be happening...
dkim_mail.private_key = key
dkim_mail.domain      = domain
dkim_mail.selector    = selector
dkim_mail.signing_algorithm  = "rsa-sha256"
dkim_mail.header_canonicalization  = "relaxed"
dkim_mail.body_canonicalization  = "relaxed"
# dkim_mail.identity  = nil
# print dkim_mail.private_key

# print "HERE"
print dkim_mail.to_s


