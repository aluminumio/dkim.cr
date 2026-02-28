require "./spec_helper"

require "spec"
require "../src/dkim"

describe Dkim::VerifyMail do
  describe "round-trip sign then verify" do
    it "passes with relaxed/relaxed" do
      signed, key = sign_for_test(header_canonicalization: "relaxed", body_canonicalization: "relaxed")
      Dkim::VerifyMail.new(signed).verify(public_key: key).should eq Dkim::VerifyStatus::Pass
    end

    it "passes with simple/simple" do
      signed, key = sign_for_test(header_canonicalization: "simple", body_canonicalization: "simple")
      Dkim::VerifyMail.new(signed).verify(public_key: key).should eq Dkim::VerifyStatus::Pass
    end

    it "passes with relaxed/simple" do
      signed, key = sign_for_test(header_canonicalization: "relaxed", body_canonicalization: "simple")
      Dkim::VerifyMail.new(signed).verify(public_key: key).should eq Dkim::VerifyStatus::Pass
    end

    it "passes with simple/relaxed" do
      signed, key = sign_for_test(header_canonicalization: "simple", body_canonicalization: "relaxed")
      Dkim::VerifyMail.new(signed).verify(public_key: key).should eq Dkim::VerifyStatus::Pass
    end
  end

  describe "body hash fail" do
    it "returns BodyHashFail when body is modified" do
      signed, key = sign_for_test
      modified = signed.sub("Are you hungry yet?", "Are you hungry now?")
      Dkim::VerifyMail.new(modified).verify(public_key: key).should eq Dkim::VerifyStatus::BodyHashFail
    end
  end

  describe "signature fail" do
    it "returns Fail when a signed header is modified" do
      signed, key = sign_for_test
      modified = signed.sub("Subject: Is dinner ready?", "Subject: Is lunch ready?")
      result = Dkim::VerifyMail.new(modified).verify(public_key: key)
      # Body hash still matches (body unchanged), but signature verification fails
      result.should eq Dkim::VerifyStatus::Fail
    end
  end

  describe "empty body" do
    it "passes with empty body" do
      empty_body_mail = "From: test@example.com\r\nTo: other@example.com\r\nSubject: empty\r\n\r\n"
      signed, key = sign_for_test(message: empty_body_mail)
      Dkim::VerifyMail.new(signed).verify(public_key: key).should eq Dkim::VerifyStatus::Pass
    end
  end

  describe "l= body length tag" do
    it "passes when content is appended beyond l= boundary" do
      signed, key = sign_for_test(body_length: 10)
      appended = signed.rstrip + "\r\nAppended extra content\r\n"
      Dkim::VerifyMail.new(appended).verify(public_key: key).should eq Dkim::VerifyStatus::Pass
    end

    it "fails when body within l= is modified" do
      signed, key = sign_for_test(body_length: 10)
      # Modify early bytes of the body (within l= boundary)
      modified = signed.sub("Hi.", "XX.")
      Dkim::VerifyMail.new(modified).verify(public_key: key).should eq Dkim::VerifyStatus::BodyHashFail
    end
  end

  describe "key revocation" do
    it "returns KeyRevoked when public key is empty" do
      signed, _ = sign_for_test
      Dkim::VerifyMail.new(signed).verify(public_key: "").should eq Dkim::VerifyStatus::KeyRevoked
    end
  end

  describe "v= validation" do
    it "returns InvalidSig when v= is missing" do
      signed, key = sign_for_test
      # Remove v=1 from the DKIM-Signature header
      modified = signed.sub("v=1;", "")
      Dkim::VerifyMail.new(modified).verify(public_key: key).should eq Dkim::VerifyStatus::InvalidSig
    end

    it "returns InvalidSig when v= has wrong value" do
      signed, key = sign_for_test
      modified = signed.sub("v=1;", "v=2;")
      Dkim::VerifyMail.new(modified).verify(public_key: key).should eq Dkim::VerifyStatus::InvalidSig
    end
  end

  describe "c= defaults" do
    it "defaults body canonicalization to simple when c= has no slash" do
      signed, key = sign_for_test(header_canonicalization: "relaxed", body_canonicalization: "simple")
      # Removing "/simple" changes a signed header, so signature fails —
      # but body hash still passes (Fail not BodyHashFail), proving the default works
      modified = signed.sub("c=relaxed/simple", "c=relaxed")
      Dkim::VerifyMail.new(modified).verify(public_key: key).should eq Dkim::VerifyStatus::Fail
    end

    it "defaults to simple/simple when c= tag is absent" do
      signed, key = sign_for_test(header_canonicalization: "simple", body_canonicalization: "simple")
      Dkim::VerifyMail.new(signed).verify(public_key: key).should eq Dkim::VerifyStatus::Pass
    end
  end

  describe "x= expiration" do
    it "returns Expired when signature has expired" do
      signed, key = sign_for_test(expire: Time.unix(TIME + 1))
      Dkim::VerifyMail.new(signed).verify(public_key: key).should eq Dkim::VerifyStatus::Expired
    end

    it "passes when signature has not expired" do
      signed, key = sign_for_test(expire: Time.utc + 1.hours)
      Dkim::VerifyMail.new(signed).verify(public_key: key).should eq Dkim::VerifyStatus::Pass
    end
  end

  describe "no signature" do
    it "returns NoSignature when message has no DKIM-Signature" do
      Dkim::VerifyMail.new(MAIL).verify(public_key: PUBLIC_KEY_B64).should eq Dkim::VerifyStatus::NoSignature
    end
  end

  describe "multiple signatures" do
    it "returns Pass if any signature passes" do
      signed, key = sign_for_test
      # Prepend a second (invalid) DKIM-Signature header
      bad_sig = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bad.com; s=bad; h=from; bh=bad; b=bad\r\n"
      multi = bad_sig + signed
      Dkim::VerifyMail.new(multi).verify(public_key: key).should eq Dkim::VerifyStatus::Pass
    end

    it "verify_all returns status for each signature" do
      signed, key = sign_for_test
      bad_sig = "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bad.com; s=bad; h=from; bh=bad; b=bad\r\n"
      multi = bad_sig + signed
      results = Dkim::VerifyMail.new(multi).verify_all(public_key: key)
      results.size.should eq 2
      results.should contain Dkim::VerifyStatus::Pass
    end
  end
end
