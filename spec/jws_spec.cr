require "./spec_helper"

describe Jose::JWS do
  describe "round-trip sign/verify" do
    it "signs and verifies a payload with ES256" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      payload = "hello world"
      jws = Jose::JWS.sign(payload, Jose::JWS::Algorithm::ES256, key)
      jws.split('.').size.should eq(3)

      decoded = Jose::JWS.verify(jws, key.public_key)
      String.new(decoded).should eq(payload)
    end

    it "signs and verifies a payload with ES384" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P384)
      payload = "hello world"
      jws = Jose::JWS.sign(payload, Jose::JWS::Algorithm::ES384, key)

      decoded = Jose::JWS.verify(jws, key.public_key)
      String.new(decoded).should eq(payload)
    end

    it "signs and verifies a payload with ES512" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
      payload = "Tang advertisement signed payload"
      jws = Jose::JWS.sign(payload, Jose::JWS::Algorithm::ES512, key)

      decoded = Jose::JWS.verify(jws, key.public_key)
      String.new(decoded).should eq(payload)
    end

    it "round-trips binary payload bytes" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      payload = Bytes[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42]
      jws = Jose::JWS.sign(payload, Jose::JWS::Algorithm::ES256, key)

      decoded = Jose::JWS.verify(jws, key.public_key)
      decoded.should eq(payload)
    end

    it "preserves additional protected header fields" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      jws = Jose::JWS.sign("p", Jose::JWS::Algorithm::ES256, key,
        header_extras: {"kid" => "key-1", "typ" => "JWT"})
      info = Jose::JWS.decode(jws)
      info[:header]["alg"].as_s.should eq("ES256")
      info[:header]["kid"].as_s.should eq("key-1")
      info[:header]["typ"].as_s.should eq("JWT")
    end
  end

  describe ".verify" do
    it "rejects a tampered payload" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      jws = Jose::JWS.sign("genuine", Jose::JWS::Algorithm::ES256, key)
      # Replace the payload section with a different base64url-encoded payload
      header_b64, _payload_b64, signature_b64 = jws.split('.')
      tampered_payload = Jose::Utils.base64url_encode("forged")
      tampered = "#{header_b64}.#{tampered_payload}.#{signature_b64}"

      expect_raises(Jose::JWS::VerificationError) do
        Jose::JWS.verify(tampered, key.public_key)
      end
    end

    it "rejects a wrong public key" do
      signer = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      other = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      jws = Jose::JWS.sign("hi", Jose::JWS::Algorithm::ES256, signer)

      expect_raises(Jose::JWS::VerificationError) do
        Jose::JWS.verify(jws, other.public_key)
      end
    end

    it "rejects an alg/curve mismatch" do
      p256 = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      p521 = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
      jws = Jose::JWS.sign("p", Jose::JWS::Algorithm::ES256, p256)

      expect_raises(Jose::JWS::VerificationError, /alg/) do
        Jose::JWS.verify(jws, p521.public_key)
      end
    end

    it "rejects an unsupported alg" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      header = Jose::Utils.base64url_encode(%({"alg":"HS256"}))
      payload = Jose::Utils.base64url_encode("p")
      sig = Jose::Utils.base64url_encode(Bytes.new(64))
      jws = "#{header}.#{payload}.#{sig}"

      expect_raises(Jose::JWS::UnsupportedAlgorithmError) do
        Jose::JWS.verify(jws, key.public_key)
      end
    end
  end

  describe ".sign" do
    it "refuses to sign with a public-only key" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256).public_key
      expect_raises(Jose::JWS::Error, /private/) do
        Jose::JWS.sign("p", Jose::JWS::Algorithm::ES256, key)
      end
    end

    it "refuses an alg/curve mismatch" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      expect_raises(Jose::JWS::Error, /curve/) do
        Jose::JWS.sign("p", Jose::JWS::Algorithm::ES512, key)
      end
    end

    it "produces a signature of the right length for the curve" do
      [
        {Jose::JWK::Curve::P256, Jose::JWS::Algorithm::ES256, 64},
        {Jose::JWK::Curve::P384, Jose::JWS::Algorithm::ES384, 96},
        {Jose::JWK::Curve::P521, Jose::JWS::Algorithm::ES512, 132},
      ].each do |curve, alg, expected_size|
        key = Jose::JWK::ECKey.generate(curve)
        jws = Jose::JWS.sign("test", alg, key)
        info = Jose::JWS.decode(jws)
        info[:signature].size.should eq(expected_size)
      end
    end
  end

  describe "DER ↔ JWS conversion" do
    # ECDSA signatures may have R or S with leading zeros (when the
    # high bit is set, DER prepends 0x00). Make sure our conversion
    # round-trips that correctly across many random signatures.
    it "round-trips through DER for many ES256 signatures" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      50.times do |i|
        jws = Jose::JWS.sign("payload #{i}", Jose::JWS::Algorithm::ES256, key)
        decoded = Jose::JWS.verify(jws, key.public_key)
        String.new(decoded).should eq("payload #{i}")
      end
    end

    it "round-trips through DER for many ES512 signatures" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
      50.times do |i|
        jws = Jose::JWS.sign("payload #{i}", Jose::JWS::Algorithm::ES512, key)
        decoded = Jose::JWS.verify(jws, key.public_key)
        String.new(decoded).should eq("payload #{i}")
      end
    end
  end
end
