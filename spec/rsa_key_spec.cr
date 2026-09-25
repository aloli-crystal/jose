require "./spec_helper"

# Fixed vectors, generated once with this shard and cross-checked against the
# `openssl` binary (see `rsa_interop_spec.cr`). They pin the verification path
# an OIDC relying party takes: a public JWK published by an identity provider,
# and an RS256 token to check against it.
module RSAFixtures
  PUBLIC_JWK = %({"kty":"RSA","n":"1KgZJR16lU76QEpKNC9EYOVCHjh1Ti14g8fzkJ_a_ewQ6c8ws1TlIdK0oZO_LnQJXH_w2cGeN9WbbDOCeEu8SyXj6pbNFkTH_ClATbh_VyqyrsvtD9_xBnnaceuJewJDJS98C-yATMiGtXKrTcXWVhZAVso-g9ilYUX82aGCspm1AmXSa5yqK7tPpywApr8i5dJsx8lQBh-BonWcx2fBo5DV9qV7hRuld2MSZMkXMlmH46hmr2PGnisf1TbGfRX2Fo2ZfDsQMTL2bo2B8KcyB6TQYUZQ-mj_ClUYy6DUm02dKm1PGvUJd4QAd8p_gSFUPuWlbs_Sxe2pffyvPubkZQ","e":"AQAB"})

  PRIVATE_JWK = %({"kty":"RSA","n":"1KgZJR16lU76QEpKNC9EYOVCHjh1Ti14g8fzkJ_a_ewQ6c8ws1TlIdK0oZO_LnQJXH_w2cGeN9WbbDOCeEu8SyXj6pbNFkTH_ClATbh_VyqyrsvtD9_xBnnaceuJewJDJS98C-yATMiGtXKrTcXWVhZAVso-g9ilYUX82aGCspm1AmXSa5yqK7tPpywApr8i5dJsx8lQBh-BonWcx2fBo5DV9qV7hRuld2MSZMkXMlmH46hmr2PGnisf1TbGfRX2Fo2ZfDsQMTL2bo2B8KcyB6TQYUZQ-mj_ClUYy6DUm02dKm1PGvUJd4QAd8p_gSFUPuWlbs_Sxe2pffyvPubkZQ","e":"AQAB","d":"FCDmImZ4KiZL1yaBABACSaahm8Etz0zMBbM5KXUMEjFUR4FCQ5MzTgCG8u1McQ3wLeZ5Sm9Cddf86mC0xoSqqbVILbYA6wzvHf3clY6zVPGYcKWiRniktH93rwVDodZMuzoTpIBKA5qOb6HPN6EUgNkB1YU2ph2tR7gLbyETwSpRrvjsdxbUQ1vCqTguel44ZFjaSNChS2fgbTFqUfEQyi9OcsY61sQzmIigNUfyefGrlJGnmMQmlNCxBzBPVJ3rpOqUZkmKd41oP-sSmIFXAgcvgxtgvvU8mlBZpnFb1jKOW1kc_a-r5uixJ_YpICxyE60h84gQydinJhRo9aisEQ","p":"8WIxD878J-TeKinhI1LpXPxYLMNhMSQc0S1y869px5pt_SB88hdl3cNR9ZIFzrFerRlQ96l_Q3IW3qmt99-_zw7haLRA9sGWpXCbP5dm57ZmIbYuLpR8_-IUQe-IHJlbqqH2kqRmYGCjzccTvaZ1kTWsxy5rvcS2P9gM8PmX_RU","q":"4YiYkjP_q5bfX8hDdYD0RS6PwYWSKJmjh9XihaESHdi5Vo7r1hMyI37x5KZvEFd1If1Zqml0FQcHemI7f-21D0a40Oi_KuDjVm-zUueMWROM7RM9h6W2shif7IDfKxqJDOsDwghH1vy1IaZ5_EmEBSS4FX5DKDVp194EqjN0PhE","dp":"TvtWGlob3-HfX-R8KlbCzQ40u9DiSHYMh9VbO6k17330Z1LuDzjguANlGflBtTQMSo9yEtd_MM5v9UOIDQdFd7biwqPYbeVCKbgC1Hfxz_e6y2UVD2C-1etfvYNnAhScDeUZDTqF1RtJ_dcZ-oAxD-aENlhWIK3xBErpUSAaP1E","dq":"qRwYcwBEhHBDm_l5A8Gm570LE-vI9WKGqVLqYJKvF-wqxMmz8rhADzefv3hArTs23D6xHkOmRCIaLF0-CiW-bu7zo8nxlgA81tI430A6D4zGTfnwWCccv5wRRnA3ZoWmICaUkchNvdmNI-dFbrPdJ1IqKgub5alvbOrQCqM8VVE","qi":"M48MNGrawHBzSfciAJreGg545zG_wOmNC5QL8RK-xilR2jeBJlFzzvKPTlSeI0n8cAsD-hxqJjfC3Fg_VgIPZYJFkit2nX6jey_PL4ywW0WLFxand2qiorO7qkdjxZzLdYWOHTe6_Bb6VCgQIyqSKoE8GuqVNNS-MpOyQkM9Aqs"})

  # Signed over {"iss":"https://idp.example","sub":"1234567890","aud":"noalyss"}
  # with a "kid" header, as an identity provider would emit.
  TOKEN = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5LTEifQ.eyJpc3MiOiJodHRwczovL2lkcC5leGFtcGxlIiwic3ViIjoiMTIzNDU2Nzg5MCIsImF1ZCI6Im5vYWx5c3MifQ.wKpLCkU_7SII6OAFNbItIO3nLx4-trkrTVO82VrZGv1z_vT_5ifpaRP_6h8MfQsSGaomnUdG3y5xx8hXyZY6MCq_2AJY0xXfpa-wUmmjAPvZkRxNBjEKfkAfBbtNr19YpF4Ft7Uu7ZIu55paQlfTbsq1KvM9NsnKD1NfrDYjZ2WSmrO8YhA5TEk3TO-xHvgBCHhGjZN56LELMupj274LSgCFsCmT3CCFasJdwWlCMG8fETK6rdvCvfhwoGV2Ss8ldp5qgNjTvEYBiNGM0mG3jXmAkEbh1HkuZ4O9x6zk-lmZKt6NAKf7y0Eb_cP6Z0nCDvU1zFf-tW4M4RLae0u_rg"

  THUMBPRINT = "iBZNT5nIIKaa4sSttPjqTiCYjc7j6wd3IlpvwiJ7OqM"
end

describe Jose::JWK::RSAKey do
  describe "generation" do
    it "generates a usable 2048-bit private key" do
      key = Jose::JWK::RSAKey.generate(2048)
      key.private?.should be_true
      key.crt_complete?.should be_true
      key.modulus_bits.should eq(2048)
      # 65537, the universal public exponent
      Jose::Utils.base64url_encode(key.e).should eq("AQAB")
    end

    it "refuses key sizes below 2048 bits" do
      expect_raises(Jose::JWK::InvalidKeyError, /2048/) do
        Jose::JWK::RSAKey.generate(1024)
      end
    end

    it "strips private members from #public_key" do
      key = Jose::JWK::RSAKey.generate(2048)
      pub = key.public_key
      pub.private?.should be_false
      pub.d.should be_nil
      pub.p.should be_nil
      pub.qi.should be_nil
      pub.n.should eq(key.n)
    end
  end

  describe "JWK serialization" do
    it "parses a public JWK" do
      key = Jose::JWK::RSAKey.from_json(RSAFixtures::PUBLIC_JWK)
      key.private?.should be_false
      key.modulus_bits.should eq(2048)
    end

    it "parses a private JWK with its CRT members" do
      key = Jose::JWK::RSAKey.from_json(RSAFixtures::PRIVATE_JWK)
      key.private?.should be_true
      key.crt_complete?.should be_true
    end

    it "omits private members unless asked" do
      key = Jose::JWK::RSAKey.from_json(RSAFixtures::PRIVATE_JWK)
      h = key.to_jwk_hash
      h.has_key?("d").should be_false
      h.has_key?("p").should be_false
      h["kty"].should eq("RSA")

      priv = key.to_jwk_hash(include_private: true)
      priv.has_key?("d").should be_true
      priv.has_key?("qi").should be_true
    end

    it "round-trips through JSON" do
      key = Jose::JWK::RSAKey.generate(2048)
      back = Jose::JWK::RSAKey.from_json(key.to_json(include_private: true))
      back.n.should eq(key.n)
      back.e.should eq(key.e)
      back.d.should eq(key.d)
      back.qi.should eq(key.qi)
    end

    it "rejects a JWK whose kty is not RSA" do
      expect_raises(Jose::JWK::UnsupportedAlgorithmError, /RSA/) do
        Jose::JWK::RSAKey.from_json(%({"kty":"EC","n":"AQAB","e":"AQAB"}))
      end
    end

    it "rejects a JWK missing its modulus" do
      expect_raises(Jose::JWK::InvalidKeyError, /missing n/) do
        Jose::JWK::RSAKey.from_json(%({"kty":"RSA","e":"AQAB"}))
      end
    end
  end

  describe "thumbprint (RFC 7638)" do
    it "matches the pinned value" do
      key = Jose::JWK::RSAKey.from_json(RSAFixtures::PRIVATE_JWK)
      key.thumbprint_base64url.should eq(RSAFixtures::THUMBPRINT)
    end

    it "ignores private members, so public and private agree" do
      key = Jose::JWK::RSAKey.generate(2048)
      key.thumbprint.should eq(key.public_key.thumbprint)
    end
  end

  describe "DER serialization" do
    it "round-trips a private key through PKCS#1" do
      key = Jose::JWK::RSAKey.generate(2048)
      back = Jose::JWK::RSAKey.from_pkcs1_private_der(key.to_pkcs1_private_der)
      back.n.should eq(key.n)
      back.d.should eq(key.d)
      back.p.should eq(key.p)
      back.qi.should eq(key.qi)
    end

    it "emits a SubjectPublicKeyInfo carrying the modulus and exponent" do
      key = Jose::JWK::RSAKey.generate(2048)

      outer = Jose::DER::Reader.new(key.to_spki_der).read_sequence
      # AlgorithmIdentifier ::= SEQUENCE { OID rsaEncryption, NULL }
      algorithm_identifier = outer.read_tagged(Jose::DER::TAG_SEQUENCE)
      expected_contents = Jose::JWK::RSAKey::ALGORITHM_IDENTIFIER[2, Jose::JWK::RSAKey::ALGORITHM_IDENTIFIER.size - 2]
      algorithm_identifier.should eq(expected_contents)

      # The BIT STRING wraps a PKCS#1 RSAPublicKey ::= SEQUENCE { n, e }
      public_key = Jose::DER::Reader.new(outer.read_bit_string).read_sequence
      public_key.read_integer.should eq(Jose::DER.strip_leading_zeros(key.n))
      public_key.read_integer.should eq(Jose::DER.strip_leading_zeros(key.e))
      outer.at_end?.should be_true
    end

    it "refuses to build a private DER without the CRT members" do
      key = Jose::JWK::RSAKey.generate(2048)
      crippled = Jose::JWK::RSAKey.new(key.n, key.e, key.d)
      crippled.private?.should be_true
      crippled.crt_complete?.should be_false
      expect_raises(Jose::JWK::InvalidKeyError, /CRT members/) do
        crippled.to_pkcs1_private_der
      end
    end
  end
end
