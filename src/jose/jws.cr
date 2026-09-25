require "json"
require "./openssl_ext"
require "./der"
require "./utils"
require "./jwk"

module Jose
  module JWS
    class Error < Exception
    end

    class VerificationError < Error
    end

    class UnsupportedAlgorithmError < Error
    end

    # Which key type an algorithm consumes.
    enum Family
      EC
      RSA
    end

    enum Algorithm
      ES256
      ES384
      ES512
      RS256
      RS384
      RS512

      def self.from_name(name : String) : Algorithm
        case name
        when "ES256" then ES256
        when "ES384" then ES384
        when "ES512" then ES512
        when "RS256" then RS256
        when "RS384" then RS384
        when "RS512" then RS512
        else
          raise UnsupportedAlgorithmError.new("unsupported alg: #{name}")
        end
      end

      def name : String
        case self
        in ES256 then "ES256"
        in ES384 then "ES384"
        in ES512 then "ES512"
        in RS256 then "RS256"
        in RS384 then "RS384"
        in RS512 then "RS512"
        end
      end

      def family : Family
        case self
        in ES256, ES384, ES512 then Family::EC
        in RS256, RS384, RS512 then Family::RSA
        end
      end

      # The curve this algorithm is bound to.
      # Raises for the RSA family, which has none — guard with `#family`.
      def curve : JWK::Curve
        case self
        in ES256 then JWK::Curve::P256
        in ES384 then JWK::Curve::P384
        in ES512 then JWK::Curve::P521
        in RS256, RS384, RS512
          raise UnsupportedAlgorithmError.new("#{name} is an RSA algorithm and has no curve")
        end
      end

      def evp_md : LibCrypto::EVP_MD
        case self
        in ES256, RS256 then LibCrypto.evp_sha256
        in ES384, RS384 then LibCrypto.evp_sha384
        in ES512, RS512 then LibCrypto.evp_sha512
        end
      end
    end

    # Sign a payload and produce a JWS Compact Serialization.
    # `header_extras` may carry additional protected header fields like
    # `kid`, `typ`, `cty`. `alg` is set automatically from `algorithm`.
    def self.sign(payload : String | Bytes, algorithm : Algorithm, key : JWK::ECKey,
                  header_extras : Hash(String, String)? = nil) : String
      raise Error.new("alg #{algorithm.name} needs an RSA key, got an EC key") if algorithm.family != Family::EC
      raise Error.new("alg #{algorithm.name} requires curve #{algorithm.curve.jwk_name}, got #{key.curve.jwk_name}") if key.curve != algorithm.curve
      raise Error.new("signing requires a private key (d)") unless key.private?

      signing_input = build_signing_input(payload, algorithm, header_extras)

      # ECDSA signatures come out of OpenSSL as DER; JWS wants raw r || s.
      der_sig = sign_raw(signing_input.to_slice, algorithm, key)
      jws_sig = der_to_jws_signature(der_sig, algorithm.curve.coordinate_octet_length)

      "#{signing_input}.#{Utils.base64url_encode(jws_sig)}"
    end

    # Sign with an RSA key (RS256 / RS384 / RS512).
    #
    # RSASSA-PKCS1-v1_5 signatures are already the raw octet string JWS
    # expects, so — unlike ECDSA — no reshaping is needed.
    def self.sign(payload : String | Bytes, algorithm : Algorithm, key : JWK::RSAKey,
                  header_extras : Hash(String, String)? = nil) : String
      raise Error.new("alg #{algorithm.name} needs an EC key, got an RSA key") if algorithm.family != Family::RSA
      raise Error.new("signing requires a private key (d)") unless key.private?

      signing_input = build_signing_input(payload, algorithm, header_extras)
      signature = sign_raw(signing_input.to_slice, algorithm, key)

      "#{signing_input}.#{Utils.base64url_encode(signature)}"
    end

    private def self.build_signing_input(payload : String | Bytes, algorithm : Algorithm,
                                         header_extras : Hash(String, String)?) : String
      header = {"alg" => algorithm.name}
      header_extras.try(&.each { |k, v| header[k] = v })
      header_b64 = Utils.base64url_encode(header.to_json)
      payload_b64 = Utils.base64url_encode(payload.is_a?(String) ? payload.to_slice : payload)
      "#{header_b64}.#{payload_b64}"
    end

    # Verify a JWS Compact Serialization. Raises VerificationError on mismatch.
    # Returns the decoded payload bytes.
    def self.verify(jws : String, key : JWK::ECKey) : Bytes
      header_b64, payload_b64, signature_b64 = split_compact(jws)
      algorithm = algorithm_from_header(header_b64)
      raise VerificationError.new("alg #{algorithm.name} needs an RSA key, got an EC key") if algorithm.family != Family::EC
      raise VerificationError.new("alg/curve mismatch") if key.curve != algorithm.curve

      jws_sig = Utils.base64url_decode(signature_b64)
      raise VerificationError.new("signature has wrong length") if jws_sig.size != 2 * algorithm.curve.coordinate_octet_length

      der_sig = jws_signature_to_der(jws_sig, algorithm.curve.coordinate_octet_length)

      signing_input = "#{header_b64}.#{payload_b64}"
      ok = verify_raw(signing_input.to_slice, der_sig, algorithm, key)
      raise VerificationError.new("signature verification failed") unless ok

      Utils.base64url_decode(payload_b64)
    end

    # Verify a JWS signed with an RSA key (RS256 / RS384 / RS512).
    #
    # This is the path an OIDC relying party takes: the identity provider
    # publishes an RSA JWK, and the ID token is signed with RS256.
    def self.verify(jws : String, key : JWK::RSAKey) : Bytes
      header_b64, payload_b64, signature_b64 = split_compact(jws)
      algorithm = algorithm_from_header(header_b64)
      raise VerificationError.new("alg #{algorithm.name} needs an EC key, got an RSA key") if algorithm.family != Family::RSA

      signature = Utils.base64url_decode(signature_b64)

      signing_input = "#{header_b64}.#{payload_b64}"
      ok = verify_raw(signing_input.to_slice, signature, algorithm, key)
      raise VerificationError.new("signature verification failed") unless ok

      Utils.base64url_decode(payload_b64)
    end

    private def self.algorithm_from_header(header_b64 : String) : Algorithm
      header = Hash(String, JSON::Any).from_json(String.new(Utils.base64url_decode(header_b64)))
      alg_name = header["alg"]?.try(&.as_s) || raise(VerificationError.new("missing alg"))
      Algorithm.from_name(alg_name)
    end

    # Sign arbitrary data, outside any JWS envelope.
    #
    # The counterpart of `.verify_signature`, and subject to the same
    # convention: the ECDSA signature comes back in OpenSSL's native ASN.1
    # DER, not the fixed-width `r || s` pair JWS mandates.
    def self.sign_data(data : Bytes, algorithm : Algorithm, key : JWK::ECKey | JWK::RSAKey) : Bytes
      case key
      in JWK::ECKey
        raise Error.new("alg #{algorithm.name} needs an RSA key, got an EC key") if algorithm.family != Family::EC
        raise Error.new("alg #{algorithm.name} requires curve #{algorithm.curve.jwk_name}, got #{key.curve.jwk_name}") if key.curve != algorithm.curve
      in JWK::RSAKey
        raise Error.new("alg #{algorithm.name} needs an EC key, got an RSA key") if algorithm.family != Family::RSA
      end
      raise Error.new("signing requires a private key (d)") unless key.private?

      sign_raw(data, algorithm, key)
    end

    # Verify a bare signature over arbitrary data, outside any JWS envelope.
    #
    # JWS is not the only thing that signs with these algorithms. WebAuthn, in
    # particular, has an authenticator sign the concatenation of its
    # authenticator data and a client-data hash, with no JOSE envelope
    # anywhere in sight.
    #
    # IMPORTANT: the signature must be in OpenSSL's native form, which for
    # ECDSA is **ASN.1 DER** — not the fixed-width `r || s` concatenation that
    # JWS itself mandates. That happens to be what WebAuthn authenticators
    # emit. RSA signatures have a single form and need no care.
    def self.verify_signature(data : Bytes, signature : Bytes, algorithm : Algorithm,
                              key : JWK::ECKey | JWK::RSAKey) : Bool
      case key
      in JWK::ECKey
        return false if algorithm.family != Family::EC
        return false if key.curve != algorithm.curve
      in JWK::RSAKey
        return false if algorithm.family != Family::RSA
      end

      verify_raw(data, signature, algorithm, key)
    end

    # Decode without verification — returns header, payload, raw JWS signature.
    def self.decode(jws : String) : NamedTuple(header: Hash(String, JSON::Any), payload: Bytes, signature: Bytes)
      header_b64, payload_b64, signature_b64 = split_compact(jws)
      header = Hash(String, JSON::Any).from_json(String.new(Utils.base64url_decode(header_b64)))
      payload = Utils.base64url_decode(payload_b64)
      signature = Utils.base64url_decode(signature_b64)
      {header: header, payload: payload, signature: signature}
    end

    private def self.split_compact(jws : String) : Tuple(String, String, String)
      parts = jws.split('.')
      raise VerificationError.new("JWS must have 3 parts, got #{parts.size}") unless parts.size == 3
      {parts[0], parts[1], parts[2]}
    end

    private def self.sign_raw(data : Bytes, algorithm : Algorithm, key : JWK::ECKey | JWK::RSAKey) : Bytes
      pkey = key.to_evp_pkey
      ctx = LibCrypto.evp_md_ctx_new
      begin
        if LibCrypto.evp_digestsigninit(ctx, nil, algorithm.evp_md, nil, pkey) != 1
          raise Error.new("EVP_DigestSignInit failed")
        end

        siglen = LibC::SizeT.new(0)
        if LibCrypto.evp_digestsign(ctx, Pointer(UInt8).null, pointerof(siglen), data.to_unsafe, data.size) != 1
          raise Error.new("EVP_DigestSign (size query) failed")
        end

        sig = Bytes.new(siglen)
        if LibCrypto.evp_digestsign(ctx, sig.to_unsafe, pointerof(siglen), data.to_unsafe, data.size) != 1
          raise Error.new("EVP_DigestSign failed")
        end
        sig[0, siglen.to_i]
      ensure
        LibCrypto.evp_md_ctx_free(ctx)
        LibCrypto.evp_pkey_free(pkey)
      end
    end

    private def self.verify_raw(data : Bytes, signature : Bytes, algorithm : Algorithm, key : JWK::ECKey | JWK::RSAKey) : Bool
      pkey = key.to_evp_pkey
      ctx = LibCrypto.evp_md_ctx_new
      begin
        if LibCrypto.evp_digestverifyinit(ctx, nil, algorithm.evp_md, nil, pkey) != 1
          raise Error.new("EVP_DigestVerifyInit failed")
        end
        result = LibCrypto.evp_digestverify(ctx, signature.to_unsafe, signature.size.to_u64, data.to_unsafe, data.size)
        result == 1
      ensure
        LibCrypto.evp_md_ctx_free(ctx)
        LibCrypto.evp_pkey_free(pkey)
      end
    end

    # Convert a DER ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
    # to the JWS r||s concatenation. `coord_len` is the byte length of
    # one coordinate for the curve (32 for P-256, 48 for P-384, 66 for P-521).
    protected def self.der_to_jws_signature(der : Bytes, coord_len : Int32) : Bytes
      seq = DER::Reader.new(der).read_sequence
      r = seq.read_integer
      s = seq.read_integer

      result = Bytes.new(2 * coord_len)
      DER.pad_left(r, coord_len).copy_to(result[0, coord_len])
      DER.pad_left(s, coord_len).copy_to(result[coord_len, coord_len])
      result
    end

    # Convert the JWS r||s concatenation back to DER for OpenSSL.
    protected def self.jws_signature_to_der(jws_sig : Bytes, coord_len : Int32) : Bytes
      DER.sequence(
        DER.concat(
          DER.integer(jws_sig[0, coord_len]),
          DER.integer(jws_sig[coord_len, coord_len])
        )
      )
    end
  end
end
