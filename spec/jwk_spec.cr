require "./spec_helper"

describe Jose::JWK::ECKey do
  # RFC 7517 §A.1 — example public key, P-256
  rfc_a1_public = <<-JSON
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "kid": "Public key used in JWS A.3 example"
    }
    JSON

  # RFC 7517 §A.2 — example private key, P-256
  rfc_a2_private = <<-JSON
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
      "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
      "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
      "use": "enc",
      "kid": "1"
    }
    JSON

  describe ".from_json" do
    it "parses a P-256 public key (RFC 7517 §A.1)" do
      key = Jose::JWK::ECKey.from_json(rfc_a1_public)
      key.curve.should eq(Jose::JWK::Curve::P256)
      key.x.size.should eq(32)
      key.y.size.should eq(32)
      key.private?.should be_false
      key.kid.should eq("Public key used in JWS A.3 example")
    end

    it "parses a P-256 private key (RFC 7517 §A.2)" do
      key = Jose::JWK::ECKey.from_json(rfc_a2_private)
      key.curve.should eq(Jose::JWK::Curve::P256)
      key.private?.should be_true
      key.d.not_nil!.size.should eq(32)
      key.kid.should eq("1")
      key.use.should eq("enc")
    end

    it "rejects unsupported curves" do
      bad = %({"kty":"EC","crv":"P-192","x":"AAAA","y":"AAAA"})
      expect_raises(Jose::JWK::UnsupportedAlgorithmError, /P-192/) do
        Jose::JWK::ECKey.from_json(bad)
      end
    end

    it "rejects non-EC kty" do
      bad = %({"kty":"RSA","crv":"P-256","x":"AAAA","y":"AAAA"})
      expect_raises(Jose::JWK::UnsupportedAlgorithmError, /kty/) do
        Jose::JWK::ECKey.from_json(bad)
      end
    end

    it "rejects coordinates of incorrect length for the curve" do
      bad = %({"kty":"EC","crv":"P-256","x":"AAAA","y":"AAAA"})
      expect_raises(Jose::JWK::InvalidKeyError, /length/) do
        Jose::JWK::ECKey.from_json(bad)
      end
    end
  end

  describe "#to_jwk_hash" do
    it "round-trips a public key" do
      key = Jose::JWK::ECKey.from_json(rfc_a1_public)
      h = key.to_jwk_hash
      h["kty"].should eq("EC")
      h["crv"].should eq("P-256")
      h["x"].should eq("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
      h["y"].should eq("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
      h.has_key?("d").should be_false
    end

    it "strips d by default for a private key" do
      key = Jose::JWK::ECKey.from_json(rfc_a2_private)
      h = key.to_jwk_hash
      h.has_key?("d").should be_false
    end

    it "exposes d when include_private is true" do
      key = Jose::JWK::ECKey.from_json(rfc_a2_private)
      h = key.to_jwk_hash(include_private: true)
      h["d"].should eq("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE")
    end
  end

  describe "#public_key" do
    it "returns a copy without the private component" do
      key = Jose::JWK::ECKey.from_json(rfc_a2_private)
      pub = key.public_key
      pub.private?.should be_false
      pub.x.should eq(key.x)
      pub.y.should eq(key.y)
    end
  end

  describe "#thumbprint" do
    it "is deterministic" do
      key = Jose::JWK::ECKey.from_json(rfc_a2_private)
      t1 = key.thumbprint
      t2 = key.thumbprint
      t1.should eq(t2)
      t1.size.should eq(32) # SHA-256 output
    end

    it "ignores private material and metadata (RFC 7638 §3.2)" do
      pub = Jose::JWK::ECKey.from_json(rfc_a1_public)
      pub_noid = Jose::JWK::ECKey.new(pub.curve, pub.x, pub.y)
      pub.thumbprint.should eq(pub_noid.thumbprint)
    end

    it "matches a reference value computed against the canonical form" do
      # Reference computed externally:
      #   echo -n '{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}' \
      #     | openssl dgst -sha256 -binary | base64 -w0
      key = Jose::JWK::ECKey.from_json(rfc_a2_private)
      key.thumbprint_base64url.should eq("cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s")
    end
  end

  describe ".generate" do
    it "generates a P-256 keypair that round-trips through JSON" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      key.private?.should be_true
      key.x.size.should eq(32)
      key.y.size.should eq(32)

      json = key.to_json(include_private: true)
      back = Jose::JWK::ECKey.from_json(json)
      back.curve.should eq(Jose::JWK::Curve::P256)
      back.x.should eq(key.x)
      back.y.should eq(key.y)
      back.d.not_nil!.should eq(key.d.not_nil!)
    end

    it "generates a P-384 keypair" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P384)
      key.x.size.should eq(48)
      key.y.size.should eq(48)
      key.d.not_nil!.size.should eq(48)
    end

    it "generates a P-521 keypair" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
      key.x.size.should eq(66)
      key.y.size.should eq(66)
      key.d.not_nil!.size.should eq(66)
    end

    it "generates distinct keys on successive calls" do
      a = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      b = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      a.d.should_not eq(b.d)
    end
  end
end
