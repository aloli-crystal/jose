require "./spec_helper"

describe CrystalJose::JWS do
  describe "round-trip sign/verify" do
    it "signs and verifies a payload with ES256" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      payload = "hello world"
      jws = CrystalJose::JWS.sign(payload, CrystalJose::JWS::Algorithm::ES256, key)
      jws.split('.').size.should eq(3)

      decoded = CrystalJose::JWS.verify(jws, key.public_key)
      String.new(decoded).should eq(payload)
    end

    it "signs and verifies a payload with ES384" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P384)
      payload = "hello world"
      jws = CrystalJose::JWS.sign(payload, CrystalJose::JWS::Algorithm::ES384, key)

      decoded = CrystalJose::JWS.verify(jws, key.public_key)
      String.new(decoded).should eq(payload)
    end

    it "signs and verifies a payload with ES512" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521)
      payload = "Tang advertisement signed payload"
      jws = CrystalJose::JWS.sign(payload, CrystalJose::JWS::Algorithm::ES512, key)

      decoded = CrystalJose::JWS.verify(jws, key.public_key)
      String.new(decoded).should eq(payload)
    end

    it "round-trips binary payload bytes" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      payload = Bytes[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42]
      jws = CrystalJose::JWS.sign(payload, CrystalJose::JWS::Algorithm::ES256, key)

      decoded = CrystalJose::JWS.verify(jws, key.public_key)
      decoded.should eq(payload)
    end

    it "preserves additional protected header fields" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      jws = CrystalJose::JWS.sign("p", CrystalJose::JWS::Algorithm::ES256, key,
        header_extras: {"kid" => "key-1", "typ" => "JWT"})
      info = CrystalJose::JWS.decode(jws)
      info[:header]["alg"].as_s.should eq("ES256")
      info[:header]["kid"].as_s.should eq("key-1")
      info[:header]["typ"].as_s.should eq("JWT")
    end
  end

  describe ".verify" do
    it "rejects a tampered payload" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      jws = CrystalJose::JWS.sign("genuine", CrystalJose::JWS::Algorithm::ES256, key)
      # Replace the payload section with a different base64url-encoded payload
      header_b64, _payload_b64, signature_b64 = jws.split('.')
      tampered_payload = CrystalJose::Utils.base64url_encode("forged")
      tampered = "#{header_b64}.#{tampered_payload}.#{signature_b64}"

      expect_raises(CrystalJose::JWS::VerificationError) do
        CrystalJose::JWS.verify(tampered, key.public_key)
      end
    end

    it "rejects a wrong public key" do
      signer = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      other = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      jws = CrystalJose::JWS.sign("hi", CrystalJose::JWS::Algorithm::ES256, signer)

      expect_raises(CrystalJose::JWS::VerificationError) do
        CrystalJose::JWS.verify(jws, other.public_key)
      end
    end

    it "rejects an alg/curve mismatch" do
      p256 = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      p521 = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521)
      jws = CrystalJose::JWS.sign("p", CrystalJose::JWS::Algorithm::ES256, p256)

      expect_raises(CrystalJose::JWS::VerificationError, /alg/) do
        CrystalJose::JWS.verify(jws, p521.public_key)
      end
    end

    it "rejects an unsupported alg" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      header = CrystalJose::Utils.base64url_encode(%({"alg":"HS256"}))
      payload = CrystalJose::Utils.base64url_encode("p")
      sig = CrystalJose::Utils.base64url_encode(Bytes.new(64))
      jws = "#{header}.#{payload}.#{sig}"

      expect_raises(CrystalJose::JWS::UnsupportedAlgorithmError) do
        CrystalJose::JWS.verify(jws, key.public_key)
      end
    end
  end

  describe ".sign" do
    it "refuses to sign with a public-only key" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256).public_key
      expect_raises(CrystalJose::JWS::Error, /private/) do
        CrystalJose::JWS.sign("p", CrystalJose::JWS::Algorithm::ES256, key)
      end
    end

    it "refuses an alg/curve mismatch" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      expect_raises(CrystalJose::JWS::Error, /curve/) do
        CrystalJose::JWS.sign("p", CrystalJose::JWS::Algorithm::ES512, key)
      end
    end

    it "produces a signature of the right length for the curve" do
      [
        {CrystalJose::JWK::Curve::P256, CrystalJose::JWS::Algorithm::ES256, 64},
        {CrystalJose::JWK::Curve::P384, CrystalJose::JWS::Algorithm::ES384, 96},
        {CrystalJose::JWK::Curve::P521, CrystalJose::JWS::Algorithm::ES512, 132},
      ].each do |curve, alg, expected_size|
        key = CrystalJose::JWK::ECKey.generate(curve)
        jws = CrystalJose::JWS.sign("test", alg, key)
        info = CrystalJose::JWS.decode(jws)
        info[:signature].size.should eq(expected_size)
      end
    end
  end

  describe "DER ↔ JWS conversion" do
    # ECDSA signatures may have R or S with leading zeros (when the
    # high bit is set, DER prepends 0x00). Make sure our conversion
    # round-trips that correctly across many random signatures.
    it "round-trips through DER for many ES256 signatures" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      50.times do |i|
        jws = CrystalJose::JWS.sign("payload #{i}", CrystalJose::JWS::Algorithm::ES256, key)
        decoded = CrystalJose::JWS.verify(jws, key.public_key)
        String.new(decoded).should eq("payload #{i}")
      end
    end

    it "round-trips through DER for many ES512 signatures" do
      key = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521)
      50.times do |i|
        jws = CrystalJose::JWS.sign("payload #{i}", CrystalJose::JWS::Algorithm::ES512, key)
        decoded = CrystalJose::JWS.verify(jws, key.public_key)
        String.new(decoded).should eq("payload #{i}")
      end
    end
  end
end
