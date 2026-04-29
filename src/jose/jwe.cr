require "json"
require "openssl"
require "openssl/digest"
require "random/secure"
require "./openssl_ext"
require "./utils"
require "./jwk"

module Jose
  module JWE
    class Error < Exception
    end

    class DecryptionError < Error
    end

    class UnsupportedAlgorithmError < Error
    end

    GCM_IV_BYTES  = 12
    GCM_TAG_BYTES = 16

    # Encrypt a plaintext under the recipient's public ECKey using
    # ECDH-ES key agreement and A256GCM content encryption (RFC 7518
    # §4.6 + §5.3). Returns a JWE Compact Serialization.
    def self.encrypt(plaintext : String | Bytes, recipient : JWK::ECKey,
                     header_extras : Hash(String, String)? = nil) : String
      bytes = plaintext.is_a?(String) ? plaintext.to_slice : plaintext
      ephemeral = JWK::ECKey.generate(recipient.curve)
      shared_secret = ecdh_derive(ephemeral, recipient.public_key)
      cek = concat_kdf_a256gcm(shared_secret)

      header = {} of String => JSON::Any
      header["alg"] = JSON::Any.new("ECDH-ES")
      header["enc"] = JSON::Any.new("A256GCM")

      epk_hash = ephemeral.public_key.to_jwk_hash
      epk_any = {} of String => JSON::Any
      epk_hash.each { |k, v| epk_any[k] = JSON::Any.new(v) }
      header["epk"] = JSON::Any.new(epk_any)

      header_extras.try(&.each { |k, v| header[k] = JSON::Any.new(v) })

      header_b64 = Utils.base64url_encode(header.to_json)
      iv = Random::Secure.random_bytes(GCM_IV_BYTES)
      aad = header_b64.to_slice
      ciphertext, tag = aes_256_gcm_encrypt(cek, iv, aad, bytes)

      [
        header_b64,
        "", # encrypted_key is empty for ECDH-ES (Direct Key Agreement)
        Utils.base64url_encode(iv),
        Utils.base64url_encode(ciphertext),
        Utils.base64url_encode(tag),
      ].join('.')
    end

    # Decrypt a JWE Compact Serialization using the recipient's
    # private ECKey. Only ECDH-ES + A256GCM is supported.
    def self.decrypt(jwe : String, recipient : JWK::ECKey) : Bytes
      raise DecryptionError.new("decryption requires a private key (d)") unless recipient.private?

      header_b64, enc_key_b64, iv_b64, ct_b64, tag_b64 = split_compact(jwe)
      header = Hash(String, JSON::Any).from_json(String.new(Utils.base64url_decode(header_b64)))

      alg = header["alg"]?.try(&.as_s) || raise(DecryptionError.new("missing alg"))
      enc = header["enc"]?.try(&.as_s) || raise(DecryptionError.new("missing enc"))
      raise UnsupportedAlgorithmError.new("unsupported alg: #{alg}") unless alg == "ECDH-ES"
      raise UnsupportedAlgorithmError.new("unsupported enc: #{enc}") unless enc == "A256GCM"
      raise DecryptionError.new("encrypted_key must be empty for ECDH-ES") unless enc_key_b64.empty?

      epk_any = header["epk"]? || raise(DecryptionError.new("missing epk"))
      epk_hash = {} of String => JSON::Any
      epk_any.as_h.each { |k, v| epk_hash[k] = v }
      epk = JWK::ECKey.from_jwk_hash(epk_hash)
      raise DecryptionError.new("epk curve does not match recipient") unless epk.curve == recipient.curve

      shared_secret = ecdh_derive(recipient, epk.public_key)
      cek = concat_kdf_a256gcm(shared_secret)

      iv = Utils.base64url_decode(iv_b64)
      ct = Utils.base64url_decode(ct_b64)
      tag = Utils.base64url_decode(tag_b64)
      raise DecryptionError.new("iv has wrong length (got #{iv.size}, expected #{GCM_IV_BYTES})") unless iv.size == GCM_IV_BYTES
      raise DecryptionError.new("tag has wrong length (got #{tag.size}, expected #{GCM_TAG_BYTES})") unless tag.size == GCM_TAG_BYTES

      aes_256_gcm_decrypt(cek, iv, header_b64.to_slice, ct, tag)
    end

    private def self.split_compact(jwe : String) : Tuple(String, String, String, String, String)
      parts = jwe.split('.')
      raise DecryptionError.new("JWE Compact must have 5 parts, got #{parts.size}") unless parts.size == 5
      {parts[0], parts[1], parts[2], parts[3], parts[4]}
    end

    # Derive the raw ECDH shared secret Z (RFC 7518 §4.6, step 1).
    # `priv` provides the private scalar, `peer` the public point.
    # Exposed for advanced use and interoperability testing.
    def self.ecdh_derive(priv : JWK::ECKey, peer : JWK::ECKey) : Bytes
      raise Error.new("ecdh_derive needs a private key") unless priv.private?
      raise Error.new("curve mismatch") unless priv.curve == peer.curve

      pkey = priv.to_evp_pkey
      peer_pkey = peer.to_evp_pkey
      ctx = LibCrypto.evp_pkey_ctx_new(pkey, nil)
      begin
        raise Error.new("EVP_PKEY_CTX_new failed") if ctx.null?
        if LibCrypto.evp_pkey_derive_init(ctx) != 1
          raise Error.new("EVP_PKEY_derive_init failed")
        end
        if LibCrypto.evp_pkey_derive_set_peer(ctx, peer_pkey) != 1
          raise Error.new("EVP_PKEY_derive_set_peer failed")
        end
        outlen = LibC::SizeT.new(0)
        if LibCrypto.evp_pkey_derive(ctx, Pointer(UInt8).null, pointerof(outlen)) != 1
          raise Error.new("EVP_PKEY_derive (size query) failed")
        end
        secret = Bytes.new(outlen)
        if LibCrypto.evp_pkey_derive(ctx, secret.to_unsafe, pointerof(outlen)) != 1
          raise Error.new("EVP_PKEY_derive failed")
        end
        secret[0, outlen.to_i]
      ensure
        LibCrypto.evp_pkey_ctx_free(ctx) unless ctx.null?
        LibCrypto.evp_pkey_free(pkey)
        LibCrypto.evp_pkey_free(peer_pkey)
      end
    end

    # Concat KDF (NIST SP 800-56A §5.8.1) specialized for A256GCM:
    #   AlgorithmID = "A256GCM"
    #   PartyUInfo = PartyVInfo = empty
    #   SuppPubInfo = keydatalen = 256 (bits)
    # SHA-256 output is exactly 32 bytes, so a single round suffices.
    # Exposed for advanced use and interoperability testing.
    def self.concat_kdf_a256gcm(z : Bytes) : Bytes
      io = IO::Memory.new
      io.write_bytes(1_u32, IO::ByteFormat::BigEndian) # counter
      io.write z

      alg_id_bytes = "A256GCM".to_slice
      io.write_bytes(alg_id_bytes.size.to_u32, IO::ByteFormat::BigEndian)
      io.write alg_id_bytes

      io.write_bytes(0_u32, IO::ByteFormat::BigEndian)   # PartyUInfo (empty)
      io.write_bytes(0_u32, IO::ByteFormat::BigEndian)   # PartyVInfo (empty)
      io.write_bytes(256_u32, IO::ByteFormat::BigEndian) # SuppPubInfo = keydatalen in bits
      # SuppPrivInfo: empty per RFC 7518 §4.6.2

      digest = OpenSSL::Digest.new("SHA256")
      digest.update(io.to_slice)
      digest.final
    end

    # AES-256-GCM encrypt. Returns {ciphertext, tag}.
    protected def self.aes_256_gcm_encrypt(key : Bytes, iv : Bytes, aad : Bytes, plaintext : Bytes) : Tuple(Bytes, Bytes)
      raise Error.new("AES-256 key must be 32 bytes, got #{key.size}") unless key.size == 32

      ctx = LibCrypto.evp_cipher_ctx_new
      begin
        cipher = LibCrypto.evp_aes_256_gcm
        # init (encrypt direction = 1), no key/iv yet
        if LibCrypto.evp_cipherinit_ex(ctx, cipher, nil, Pointer(UInt8).null, Pointer(UInt8).null, 1) != 1
          raise Error.new("EVP_CipherInit_ex (encrypt, init) failed")
        end
        if LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_SET_IVLEN, iv.size, Pointer(Void).null) != 1
          raise Error.new("EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed")
        end
        if LibCrypto.evp_cipherinit_ex(ctx, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), nil, key.to_unsafe, iv.to_unsafe, 1) != 1
          raise Error.new("EVP_CipherInit_ex (encrypt, key/iv) failed")
        end

        outlen = 0_i32
        # AAD update — pass NULL output and AAD bytes
        if !aad.empty?
          if LibCrypto.evp_cipherupdate(ctx, Pointer(UInt8).null, pointerof(outlen), aad.to_unsafe, aad.size) != 1
            raise Error.new("EVP_CipherUpdate (AAD) failed")
          end
        end

        ciphertext = Bytes.new(plaintext.size)
        if LibCrypto.evp_cipherupdate(ctx, ciphertext.to_unsafe, pointerof(outlen), plaintext.to_unsafe, plaintext.size) != 1
          raise Error.new("EVP_CipherUpdate (plaintext) failed")
        end
        produced = outlen
        final_buf = Bytes.new(16)
        if LibCrypto.evp_cipherfinal_ex(ctx, final_buf.to_unsafe, pointerof(outlen)) != 1
          raise Error.new("EVP_CipherFinal_ex failed")
        end
        # GCM produces no extra bytes at finalize for plaintext
        produced += outlen

        tag = Bytes.new(GCM_TAG_BYTES)
        if LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_GET_TAG, GCM_TAG_BYTES, tag.to_unsafe.as(Void*)) != 1
          raise Error.new("EVP_CIPHER_CTX_ctrl(GET_TAG) failed")
        end

        {ciphertext[0, produced], tag}
      ensure
        LibCrypto.evp_cipher_ctx_free(ctx)
      end
    end

    # AES-256-GCM decrypt. Raises DecryptionError on tag mismatch.
    protected def self.aes_256_gcm_decrypt(key : Bytes, iv : Bytes, aad : Bytes, ciphertext : Bytes, tag : Bytes) : Bytes
      raise Error.new("AES-256 key must be 32 bytes, got #{key.size}") unless key.size == 32
      raise Error.new("tag must be 16 bytes, got #{tag.size}") unless tag.size == GCM_TAG_BYTES

      ctx = LibCrypto.evp_cipher_ctx_new
      begin
        cipher = LibCrypto.evp_aes_256_gcm
        if LibCrypto.evp_cipherinit_ex(ctx, cipher, nil, Pointer(UInt8).null, Pointer(UInt8).null, 0) != 1
          raise Error.new("EVP_CipherInit_ex (decrypt, init) failed")
        end
        if LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_SET_IVLEN, iv.size, Pointer(Void).null) != 1
          raise Error.new("EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed")
        end
        if LibCrypto.evp_cipherinit_ex(ctx, Pointer(Void).null.as(LibCrypto::EVP_CIPHER), nil, key.to_unsafe, iv.to_unsafe, 0) != 1
          raise Error.new("EVP_CipherInit_ex (decrypt, key/iv) failed")
        end

        outlen = 0_i32
        if !aad.empty?
          if LibCrypto.evp_cipherupdate(ctx, Pointer(UInt8).null, pointerof(outlen), aad.to_unsafe, aad.size) != 1
            raise Error.new("EVP_CipherUpdate (AAD) failed")
          end
        end

        plaintext = Bytes.new(ciphertext.size)
        if LibCrypto.evp_cipherupdate(ctx, plaintext.to_unsafe, pointerof(outlen), ciphertext.to_unsafe, ciphertext.size) != 1
          raise Error.new("EVP_CipherUpdate (ciphertext) failed")
        end
        produced = outlen

        if LibCrypto.evp_cipher_ctx_ctrl(ctx, LibCrypto::EVP_CTRL_GCM_SET_TAG, tag.size, tag.to_unsafe.as(Void*)) != 1
          raise Error.new("EVP_CIPHER_CTX_ctrl(SET_TAG) failed")
        end

        final_buf = Bytes.new(16)
        if LibCrypto.evp_cipherfinal_ex(ctx, final_buf.to_unsafe, pointerof(outlen)) != 1
          raise DecryptionError.new("authentication tag mismatch")
        end
        produced += outlen

        plaintext[0, produced]
      ensure
        LibCrypto.evp_cipher_ctx_free(ctx)
      end
    end
  end
end
