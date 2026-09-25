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

describe Jose::JWS do
  describe "RSA signatures" do
    it "signs and verifies with RS256" do
      key = Jose::JWK::RSAKey.generate(2048)
      payload = "hello world"
      jws = Jose::JWS.sign(payload, Jose::JWS::Algorithm::RS256, key)
      jws.split('.').size.should eq(3)

      String.new(Jose::JWS.verify(jws, key.public_key)).should eq(payload)
    end

    it "signs and verifies with RS384" do
      key = Jose::JWK::RSAKey.generate(2048)
      jws = Jose::JWS.sign("hello world", Jose::JWS::Algorithm::RS384, key)
      String.new(Jose::JWS.verify(jws, key.public_key)).should eq("hello world")
    end

    it "signs and verifies with RS512" do
      key = Jose::JWK::RSAKey.generate(2048)
      jws = Jose::JWS.sign("hello world", Jose::JWS::Algorithm::RS512, key)
      String.new(Jose::JWS.verify(jws, key.public_key)).should eq("hello world")
    end

    it "round-trips binary payload bytes" do
      key = Jose::JWK::RSAKey.generate(2048)
      payload = Bytes[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42]
      jws = Jose::JWS.sign(payload, Jose::JWS::Algorithm::RS256, key)
      Jose::JWS.verify(jws, key.public_key).should eq(payload)
    end

    it "carries header extras such as kid" do
      key = Jose::JWK::RSAKey.generate(2048)
      jws = Jose::JWS.sign("x", Jose::JWS::Algorithm::RS256, key, {"kid" => "idp-2026"})
      Jose::JWS.decode(jws)[:header]["kid"].as_s.should eq("idp-2026")
    end

    it "verifies a pinned token against a pinned public JWK" do
      key = Jose::JWK::RSAKey.from_json(RSAFixtures::PUBLIC_JWK)
      payload = String.new(Jose::JWS.verify(RSAFixtures::TOKEN, key))
      payload.should contain(%("iss":"https://idp.example"))
      payload.should contain(%("aud":"noalyss"))
    end

    it "rejects a tampered payload" do
      key = Jose::JWK::RSAKey.from_json(RSAFixtures::PUBLIC_JWK)
      header, _payload, signature = RSAFixtures::TOKEN.split('.')
      forged = "#{header}.#{Jose::Utils.base64url_encode(%({"iss":"attacker"}))}.#{signature}"

      expect_raises(Jose::JWS::VerificationError, /verification failed/) do
        Jose::JWS.verify(forged, key)
      end
    end

    it "rejects a signature made by a different key" do
      signer = Jose::JWK::RSAKey.generate(2048)
      other = Jose::JWK::RSAKey.generate(2048)
      jws = Jose::JWS.sign("x", Jose::JWS::Algorithm::RS256, signer)

      expect_raises(Jose::JWS::VerificationError, /verification failed/) do
        Jose::JWS.verify(jws, other.public_key)
      end
    end

    it "refuses to sign with a public key" do
      key = Jose::JWK::RSAKey.generate(2048).public_key
      expect_raises(Jose::JWS::Error, /private key/) do
        Jose::JWS.sign("x", Jose::JWS::Algorithm::RS256, key)
      end
    end
  end

  describe "algorithm families" do
    it "reports the family of each algorithm" do
      Jose::JWS::Algorithm::ES256.family.should eq(Jose::JWS::Family::EC)
      Jose::JWS::Algorithm::RS256.family.should eq(Jose::JWS::Family::RSA)
    end

    it "refuses an RSA algorithm with an EC key" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      expect_raises(Jose::JWS::Error, /needs an RSA key/) do
        Jose::JWS.sign("x", Jose::JWS::Algorithm::RS256, key)
      end
    end

    it "refuses an EC algorithm with an RSA key" do
      key = Jose::JWK::RSAKey.generate(2048)
      expect_raises(Jose::JWS::Error, /needs an EC key/) do
        Jose::JWS.sign("x", Jose::JWS::Algorithm::ES256, key)
      end
    end

    it "refuses to verify an RS256 token with an EC key" do
      ec = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      expect_raises(Jose::JWS::VerificationError, /needs an RSA key/) do
        Jose::JWS.verify(RSAFixtures::TOKEN, ec)
      end
    end

    it "has no curve for the RSA family" do
      expect_raises(Jose::JWS::UnsupportedAlgorithmError, /no curve/) do
        Jose::JWS::Algorithm::RS256.curve
      end
    end
  end
end

describe "Jose::JWS.verify_signature" do
  it "verifies a bare RSA signature over arbitrary data" do
    key = Jose::JWK::RSAKey.generate(2048)
    data = "authenticator data || client data hash".to_slice
    jws = Jose::JWS.sign(data, Jose::JWS::Algorithm::RS256, key)
    signature = Jose::Utils.base64url_decode(jws.split('.')[2])
    signing_input = jws.split('.')[0, 2].join('.').to_slice

    Jose::JWS.verify_signature(signing_input, signature, Jose::JWS::Algorithm::RS256, key.public_key).should be_true
  end

  it "verifies a bare ECDSA signature given in DER form" do
    key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
    jws = Jose::JWS.sign("payload", Jose::JWS::Algorithm::ES256, key)
    signing_input = jws.split('.')[0, 2].join('.').to_slice

    # JWS carries r || s; OpenSSL — and WebAuthn — want DER.
    raw = Jose::Utils.base64url_decode(jws.split('.')[2])
    der = Jose::DER.sequence(
      Jose::DER.concat(Jose::DER.integer(raw[0, 32]), Jose::DER.integer(raw[32, 32]))
    )

    Jose::JWS.verify_signature(signing_input, der, Jose::JWS::Algorithm::ES256, key.public_key).should be_true
  end

  it "returns false on a mismatched signature" do
    key = Jose::JWK::RSAKey.generate(2048)
    other = Jose::JWK::RSAKey.generate(2048)
    jws = Jose::JWS.sign("payload", Jose::JWS::Algorithm::RS256, key)
    signature = Jose::Utils.base64url_decode(jws.split('.')[2])
    signing_input = jws.split('.')[0, 2].join('.').to_slice

    Jose::JWS.verify_signature(signing_input, signature, Jose::JWS::Algorithm::RS256, other.public_key).should be_false
  end

  it "returns false when the algorithm family does not match the key" do
    key = Jose::JWK::RSAKey.generate(2048)
    Jose::JWS.verify_signature("x".to_slice, Bytes[1, 2, 3], Jose::JWS::Algorithm::ES256, key).should be_false
  end
end

describe "Jose::JWS.sign_data" do
  it "round-trips a bare RSA signature with verify_signature" do
    key = Jose::JWK::RSAKey.generate(2048)
    data = "authenticator data || client data hash".to_slice
    signature = Jose::JWS.sign_data(data, Jose::JWS::Algorithm::RS256, key)

    Jose::JWS.verify_signature(data, signature, Jose::JWS::Algorithm::RS256, key.public_key).should be_true
  end

  it "round-trips a bare ECDSA signature with verify_signature" do
    key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
    data = "authenticator data || client data hash".to_slice
    signature = Jose::JWS.sign_data(data, Jose::JWS::Algorithm::ES256, key)

    # ASN.1 DER: SEQUENCE { INTEGER r, INTEGER s }
    signature[0].should eq(0x30)
    Jose::JWS.verify_signature(data, signature, Jose::JWS::Algorithm::ES256, key.public_key).should be_true
  end

  it "does not verify against different data" do
    key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
    signature = Jose::JWS.sign_data("one".to_slice, Jose::JWS::Algorithm::ES256, key)

    Jose::JWS.verify_signature("two".to_slice, signature, Jose::JWS::Algorithm::ES256, key.public_key).should be_false
  end

  it "refuses to sign with a public key" do
    key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256).public_key
    expect_raises(Jose::JWS::Error, /private key/) do
      Jose::JWS.sign_data("x".to_slice, Jose::JWS::Algorithm::ES256, key)
    end
  end
end
