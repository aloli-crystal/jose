require "./spec_helper"

describe CrystalJose do
  it "exposes a version" do
    CrystalJose::VERSION.should eq("0.1.0")
  end
end

describe CrystalJose::Utils do
  describe ".base64url_encode" do
    it "encodes bytes without padding" do
      CrystalJose::Utils.base64url_encode("hello".to_slice).should eq("aGVsbG8")
    end

    it "encodes a string" do
      CrystalJose::Utils.base64url_encode("hello").should eq("aGVsbG8")
    end
  end

  describe ".base64url_decode" do
    it "decodes a base64url string without padding" do
      String.new(CrystalJose::Utils.base64url_decode("aGVsbG8")).should eq("hello")
    end

    it "round-trips arbitrary bytes" do
      original = Bytes[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF]
      encoded = CrystalJose::Utils.base64url_encode(original)
      CrystalJose::Utils.base64url_decode(encoded).should eq(original)
    end
  end
end
