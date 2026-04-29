require "json"
require "./openssl_ext"
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

    enum Algorithm
      ES256
      ES384
      ES512

      def self.from_name(name : String) : Algorithm
        case name
        when "ES256" then ES256
        when "ES384" then ES384
        when "ES512" then ES512
        else
          raise UnsupportedAlgorithmError.new("unsupported alg: #{name}")
        end
      end

      def name : String
        case self
        in ES256 then "ES256"
        in ES384 then "ES384"
        in ES512 then "ES512"
        end
      end

      def curve : JWK::Curve
        case self
        in ES256 then JWK::Curve::P256
        in ES384 then JWK::Curve::P384
        in ES512 then JWK::Curve::P521
        end
      end

      def evp_md : LibCrypto::EVP_MD
        case self
        in ES256 then LibCrypto.evp_sha256
        in ES384 then LibCrypto.evp_sha384
        in ES512 then LibCrypto.evp_sha512
        end
      end
    end

    # Sign a payload and produce a JWS Compact Serialization.
    # `header_extras` may carry additional protected header fields like
    # `kid`, `typ`, `cty`. `alg` is set automatically from `algorithm`.
    def self.sign(payload : String | Bytes, algorithm : Algorithm, key : JWK::ECKey,
                  header_extras : Hash(String, String)? = nil) : String
      raise Error.new("alg #{algorithm.name} requires curve #{algorithm.curve.jwk_name}, got #{key.curve.jwk_name}") if key.curve != algorithm.curve
      raise Error.new("signing requires a private key (d)") unless key.private?

      header = {"alg" => algorithm.name}
      header_extras.try(&.each { |k, v| header[k] = v })
      header_b64 = Utils.base64url_encode(header.to_json)
      payload_b64 = Utils.base64url_encode(payload.is_a?(String) ? payload.to_slice : payload)
      signing_input = "#{header_b64}.#{payload_b64}"

      der_sig = sign_raw_der(signing_input.to_slice, algorithm, key)
      jws_sig = der_to_jws_signature(der_sig, algorithm.curve.coordinate_octet_length)

      "#{signing_input}.#{Utils.base64url_encode(jws_sig)}"
    end

    # Verify a JWS Compact Serialization. Raises VerificationError on mismatch.
    # Returns the decoded payload bytes.
    def self.verify(jws : String, key : JWK::ECKey) : Bytes
      header_b64, payload_b64, signature_b64 = split_compact(jws)
      header_json = Utils.base64url_decode(header_b64)
      header = Hash(String, JSON::Any).from_json(String.new(header_json))

      alg_name = header["alg"]?.try(&.as_s) || raise(VerificationError.new("missing alg"))
      algorithm = Algorithm.from_name(alg_name)
      raise VerificationError.new("alg/curve mismatch") if key.curve != algorithm.curve

      jws_sig = Utils.base64url_decode(signature_b64)
      raise VerificationError.new("signature has wrong length") if jws_sig.size != 2 * algorithm.curve.coordinate_octet_length

      der_sig = jws_signature_to_der(jws_sig, algorithm.curve.coordinate_octet_length)

      signing_input = "#{header_b64}.#{payload_b64}"
      ok = verify_raw_der(signing_input.to_slice, der_sig, algorithm, key)
      raise VerificationError.new("signature verification failed") unless ok

      Utils.base64url_decode(payload_b64)
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

    private def self.sign_raw_der(data : Bytes, algorithm : Algorithm, key : JWK::ECKey) : Bytes
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

    private def self.verify_raw_der(data : Bytes, der_sig : Bytes, algorithm : Algorithm, key : JWK::ECKey) : Bool
      pkey = key.to_evp_pkey
      ctx = LibCrypto.evp_md_ctx_new
      begin
        if LibCrypto.evp_digestverifyinit(ctx, nil, algorithm.evp_md, nil, pkey) != 1
          raise Error.new("EVP_DigestVerifyInit failed")
        end
        result = LibCrypto.evp_digestverify(ctx, der_sig.to_unsafe, der_sig.size.to_u64, data.to_unsafe, data.size)
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
      io = IO::Memory.new(der)
      tag = io.read_byte || raise(Error.new("DER: empty"))
      raise Error.new("DER: expected SEQUENCE") unless tag == 0x30_u8

      _seq_len = read_der_length(io)
      r = strip_left_zeros(read_der_integer(io))
      s = strip_left_zeros(read_der_integer(io))

      result = Bytes.new(2 * coord_len)
      pad_left(r, coord_len).copy_to(result[0, coord_len])
      pad_left(s, coord_len).copy_to(result[coord_len, coord_len])
      result
    end

    # Convert the JWS r||s concatenation back to DER for OpenSSL.
    protected def self.jws_signature_to_der(jws_sig : Bytes, coord_len : Int32) : Bytes
      r = strip_left_zeros(jws_sig[0, coord_len])
      s = strip_left_zeros(jws_sig[coord_len, coord_len])

      r_der = encode_der_integer(r)
      s_der = encode_der_integer(s)

      seq_payload = Bytes.new(r_der.size + s_der.size)
      r_der.copy_to(seq_payload[0, r_der.size])
      s_der.copy_to(seq_payload[r_der.size, s_der.size])
      encode_der_sequence(seq_payload)
    end

    private def self.read_der_length(io : IO::Memory) : Int32
      first = io.read_byte || raise(Error.new("DER: truncated length"))
      if first < 0x80
        first.to_i32
      else
        n = (first & 0x7f).to_i32
        result = 0
        n.times do
          b = io.read_byte || raise(Error.new("DER: truncated length"))
          result = (result << 8) | b.to_i32
        end
        result
      end
    end

    private def self.read_der_integer(io : IO::Memory) : Bytes
      tag = io.read_byte || raise(Error.new("DER: missing INTEGER"))
      raise Error.new("DER: expected INTEGER, got 0x#{tag.to_s(16)}") unless tag == 0x02_u8
      len = read_der_length(io)
      buf = Bytes.new(len)
      io.read_fully(buf)
      buf
    end

    private def self.encode_der_integer(magnitude : Bytes) : Bytes
      # Per DER, INTEGER is signed two's complement big-endian.
      # If the high bit of the first byte is 1, prepend 0x00 to keep
      # the value non-negative.
      needs_pad = !magnitude.empty? && (magnitude[0] & 0x80) != 0
      content_size = (magnitude.empty? ? 1 : magnitude.size) + (needs_pad ? 1 : 0)

      io = IO::Memory.new
      io.write_byte 0x02_u8
      write_der_length(io, content_size)
      if magnitude.empty?
        io.write_byte 0x00_u8
      else
        io.write_byte 0x00_u8 if needs_pad
        io.write magnitude
      end
      io.to_slice.dup
    end

    private def self.encode_der_sequence(payload : Bytes) : Bytes
      io = IO::Memory.new
      io.write_byte 0x30_u8
      write_der_length(io, payload.size)
      io.write payload
      io.to_slice.dup
    end

    private def self.write_der_length(io : IO, len : Int32)
      if len < 0x80
        io.write_byte len.to_u8
      elsif len < 0x100
        io.write_byte 0x81_u8
        io.write_byte len.to_u8
      elsif len < 0x10000
        io.write_byte 0x82_u8
        io.write_byte ((len >> 8) & 0xff).to_u8
        io.write_byte (len & 0xff).to_u8
      else
        raise Error.new("DER length too large: #{len}")
      end
    end

    private def self.strip_left_zeros(bytes : Bytes) : Bytes
      i = 0
      while i < bytes.size - 1 && bytes[i] == 0
        i += 1
      end
      bytes[i, bytes.size - i]
    end

    private def self.pad_left(bytes : Bytes, target_len : Int32) : Bytes
      raise Error.new("integer too large for curve") if bytes.size > target_len
      padded = Bytes.new(target_len)
      bytes.copy_to(padded[target_len - bytes.size, bytes.size])
      padded
    end
  end
end
