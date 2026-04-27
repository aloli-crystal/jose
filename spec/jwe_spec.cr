require "./spec_helper"

describe CrystalJose::JWE do
  describe "round-trip encrypt/decrypt" do
    it "round-trips a P-256 ECDH-ES + A256GCM payload" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      payload = "the quick brown fox jumps over the lazy dog"
      jwe = CrystalJose::JWE.encrypt(payload, recipient.public_key)
      jwe.split('.').size.should eq(5)

      plaintext = CrystalJose::JWE.decrypt(jwe, recipient)
      String.new(plaintext).should eq(payload)
    end

    it "round-trips a P-384 payload" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P384)
      payload = "P-384 payload"
      jwe = CrystalJose::JWE.encrypt(payload, recipient.public_key)
      plaintext = CrystalJose::JWE.decrypt(jwe, recipient)
      String.new(plaintext).should eq(payload)
    end

    it "round-trips a P-521 payload" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521)
      payload = "Tang ECDH P-521"
      jwe = CrystalJose::JWE.encrypt(payload, recipient.public_key)
      plaintext = CrystalJose::JWE.decrypt(jwe, recipient)
      String.new(plaintext).should eq(payload)
    end

    it "round-trips empty plaintext" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      jwe = CrystalJose::JWE.encrypt("", recipient.public_key)
      plaintext = CrystalJose::JWE.decrypt(jwe, recipient)
      plaintext.size.should eq(0)
    end

    it "round-trips binary plaintext" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      payload = Bytes.new(1024) { |i| (i & 0xff).to_u8 }
      jwe = CrystalJose::JWE.encrypt(payload, recipient.public_key)
      plaintext = CrystalJose::JWE.decrypt(jwe, recipient)
      plaintext.should eq(payload)
    end

    it "produces a different ciphertext each time (epk + iv differ)" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      payload = "same input"
      a = CrystalJose::JWE.encrypt(payload, recipient.public_key)
      b = CrystalJose::JWE.encrypt(payload, recipient.public_key)
      a.should_not eq(b)
    end

    it "preserves additional protected header fields" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      jwe = CrystalJose::JWE.encrypt("hi", recipient.public_key,
        header_extras: {"kid" => "k1", "cty" => "application/octet-stream"})

      header_b64 = jwe.split('.').first
      header = Hash(String, JSON::Any).from_json(String.new(CrystalJose::Utils.base64url_decode(header_b64)))
      header["kid"].as_s.should eq("k1")
      header["cty"].as_s.should eq("application/octet-stream")
    end
  end

  describe ".decrypt" do
    it "rejects a JWE with the wrong recipient key" do
      r1 = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      r2 = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      jwe = CrystalJose::JWE.encrypt("secret", r1.public_key)

      expect_raises(CrystalJose::JWE::DecryptionError) do
        CrystalJose::JWE.decrypt(jwe, r2)
      end
    end

    it "rejects a tampered ciphertext (auth tag fails)" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      jwe = CrystalJose::JWE.encrypt("secret", recipient.public_key)
      header_b64, enc_key, iv_b64, ct_b64, tag_b64 = jwe.split('.')

      ct_bytes = CrystalJose::Utils.base64url_decode(ct_b64)
      ct_bytes[0] ^= 0xff_u8
      tampered_ct = CrystalJose::Utils.base64url_encode(ct_bytes)
      tampered = "#{header_b64}.#{enc_key}.#{iv_b64}.#{tampered_ct}.#{tag_b64}"

      expect_raises(CrystalJose::JWE::DecryptionError, /tag/) do
        CrystalJose::JWE.decrypt(tampered, recipient)
      end
    end

    it "rejects a tampered header (AAD changes invalidate the tag)" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      jwe = CrystalJose::JWE.encrypt("secret", recipient.public_key)
      header_b64, enc_key, iv_b64, ct_b64, tag_b64 = jwe.split('.')

      header = Hash(String, JSON::Any).from_json(String.new(CrystalJose::Utils.base64url_decode(header_b64)))
      header["kid"] = JSON::Any.new("forged")
      tampered_header = CrystalJose::Utils.base64url_encode(header.to_json)
      tampered = "#{tampered_header}.#{enc_key}.#{iv_b64}.#{ct_b64}.#{tag_b64}"

      expect_raises(CrystalJose::JWE::DecryptionError, /tag/) do
        CrystalJose::JWE.decrypt(tampered, recipient)
      end
    end

    it "rejects an unsupported alg" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      header = {"alg" => "RSA-OAEP", "enc" => "A256GCM"}
      header_b64 = CrystalJose::Utils.base64url_encode(header.to_json)
      jwe = "#{header_b64}.somekey.someiv.somect.sometag"

      expect_raises(CrystalJose::JWE::UnsupportedAlgorithmError, /RSA-OAEP/) do
        CrystalJose::JWE.decrypt(jwe, recipient)
      end
    end

    it "rejects an unsupported enc" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      header = {"alg" => "ECDH-ES", "enc" => "A128CBC-HS256"}
      header_b64 = CrystalJose::Utils.base64url_encode(header.to_json)
      jwe = "#{header_b64}.somekey.someiv.somect.sometag"

      expect_raises(CrystalJose::JWE::UnsupportedAlgorithmError, /A128CBC-HS256/) do
        CrystalJose::JWE.decrypt(jwe, recipient)
      end
    end

    it "rejects an epk on a different curve than the recipient" do
      r256 = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      r521 = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P521)
      jwe = CrystalJose::JWE.encrypt("hi", r256.public_key)

      expect_raises(CrystalJose::JWE::DecryptionError) do
        CrystalJose::JWE.decrypt(jwe, r521)
      end
    end

    it "rejects decryption with a public-only recipient key" do
      recipient = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      jwe = CrystalJose::JWE.encrypt("hi", recipient.public_key)

      expect_raises(CrystalJose::JWE::DecryptionError, /private/) do
        CrystalJose::JWE.decrypt(jwe, recipient.public_key)
      end
    end
  end

  describe "Concat KDF determinism" do
    it "produces the same CEK for the same shared secret" do
      r = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      e = CrystalJose::JWK::ECKey.generate(CrystalJose::JWK::Curve::P256)
      z1 = CrystalJose::JWE.ecdh_derive(e, r.public_key)
      z2 = CrystalJose::JWE.ecdh_derive(r, e.public_key)
      z1.should eq(z2)

      cek1 = CrystalJose::JWE.concat_kdf_a256gcm(z1)
      cek2 = CrystalJose::JWE.concat_kdf_a256gcm(z2)
      cek1.should eq(cek2)
      cek1.size.should eq(32)
    end
  end
end
