
if ARGV.size < 1
  puts "Usage: dkimvrfy MAILFILE"
  exit 0
end

require "./dkim"

mailfile = ARGV.pop

mail = mailfile ? File.read(mailfile) : STDIN.gets_to_end
if mail
  mail = mail.gsub(/\r?\n/, "\r\n")
end

#	pubkey = key.public_key
#	if pubkey.verify(OpenSSL::Digest::SHA256.new, signature, data)


dkim_mail = Dkim::VerifyMail.new(mail)

dkim_mail.verify
