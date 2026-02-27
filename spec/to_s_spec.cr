require "./spec_helper"

require "spec"
require "../src/dkim"

describe Dkim::Header do
  describe "#to_s" do
    it "returns key:value, not an object reference" do
      header = Dkim::Header.new("From", " Joe <joe@example.com>")
      str = header.to_s
      str.should contain("From")
      str.should contain("joe@example.com")
      str.should_not match(/Dkim::Header:0x/)
    end

    it "allows extracting the sender domain via split chain" do
      header = Dkim::Header.new("From", " Joe <joe@example.com>")
      domain = header.to_s.split("<").last.split(">").first.split("@").last
      domain.should eq "example.com"
    end

    it "handles bare email addresses without angle brackets" do
      header = Dkim::Header.new("From", " joe@example.com")
      domain = header.to_s.split("<").last.split(">").first.split("@").last
      domain.should eq "example.com"
    end
  end
end

describe Dkim::TagValueList do
  describe "#to_s" do
    it "returns tag-value pairs, not an object reference" do
      tvl = Dkim::TagValueList.parse("v=1; a=rsa-sha256; d=example.com; s=sel")
      str = tvl.to_s
      str.should contain("v=1")
      str.should contain("a=rsa-sha256")
      str.should contain("d=example.com")
      str.should contain("s=sel")
      str.should_not match(/Dkim::TagValueList:0x/)
    end

    it "roundtrips through parse and to_s" do
      original = "v=1; a=rsa-sha256; d=example.com; s=brisbane"
      parsed = Dkim::TagValueList.parse(original)
      parsed.to_s.should eq original
    end

    it "preserves tag ordering from original header" do
      tvl = Dkim::TagValueList.parse("d=example.com; s=sel; a=rsa-sha256; v=1")
      tvl.to_s.should eq "d=example.com; s=sel; a=rsa-sha256; v=1"
    end

    it "allows splitting on b= for DKIM verification" do
      sig = "v=1; a=rsa-sha256; d=example.com; s=sel; bh=abc123; h=from:to; b=SIGNATURE"
      tvl = Dkim::TagValueList.parse(sig)
      # This is exactly what verify_mail.cr line 140 does
      stripped = tvl.to_s.split("b=").first + "b="
      stripped.should contain("v=1")
      stripped.should contain("d=example.com")
      stripped.should contain("bh=abc123")
      stripped.should end_with("b=")
      stripped.should_not contain("SIGNATURE")
    end

    it "does not match bh= when splitting on b=" do
      sig = "v=1; bh=bodyhash; b=signature"
      tvl = Dkim::TagValueList.parse(sig)
      stripped = tvl.to_s.split("b=").first + "b="
      stripped.should contain("bh=bodyhash")
    end
  end
end

describe Dkim::DkimHeader do
  describe "#to_s" do
    it "returns the DKIM header string, not an object reference" do
      dh = Dkim::DkimHeader.new
      dh["v"] = "1"
      dh["a"] = "rsa-sha256"
      dh["d"] = "example.com"
      str = dh.to_s
      str.should contain("example.com")
      str.should_not match(/Dkim::DkimHeader:0x/)
    end
  end
end
