
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

dkim_mail = Dkim::VerifyMail.new(mail)

result = dkim_mail.verify
case result
when Dkim::VerifyStatus::Pass
  puts "DKIM Verified"
when Dkim::VerifyStatus::NoSignature
  puts "WARNING: No DKIM signature found"
  exit 1
when Dkim::VerifyStatus::BodyHashFail
  puts "WARNING: DKIM body hash mismatch"
  exit 1
when Dkim::VerifyStatus::KeyRevoked
  puts "WARNING: DKIM key has been revoked"
  exit 1
when Dkim::VerifyStatus::Expired
  puts "WARNING: DKIM signature has expired"
  exit 1
when Dkim::VerifyStatus::NoKey
  puts "WARNING: No DKIM public key found"
  exit 1
when Dkim::VerifyStatus::InvalidSig
  puts "WARNING: Invalid DKIM signature"
  exit 1
else
  puts "WARNING: DKIM verification failed"
  exit 1
end
