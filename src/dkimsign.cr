
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

dkim_mail =  Dkim::SignedMail.new(mail, 
                                  domain: domain, 
                                  private_key: key, 
                                  selector: selector)

print dkim_mail.to_s


