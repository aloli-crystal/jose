require "openssl/lib_crypto"

# Extended LibCrypto bindings for EC, ECDSA, ECDH, RSA and AES-GCM
# operations needed by JOSE (RFC 7515-7519).
#
# Crystal stdlib's `OpenSSL` module exposes very little of EC, so we
# bind the relevant `libcrypto` symbols directly here. We rely on
# OpenSSL ≥ 3.0 (validated against 3.6.2 in the test environment).
lib LibCrypto
  type Bignum = Void*
  type BignumCtx = Void*
  type EcGroup = Void*
  type EcPoint = Void*
  type EvpPKey = Void*
  type EvpPkeyCtx = Void*
  # EVP_CIPHER, EVP_CIPHER_CTX, EC_KEY, EVP_MD, EVP_MD_CTX are already
  # declared by stdlib, as are evp_md_ctx_new/free, evp_cipher_ctx_new/free,
  # evp_cipherinit_ex, evp_cipherupdate, evp_cipherfinal_ex,
  # evp_sha256/384/512.

  fun ec_key_generate_key = EC_KEY_generate_key(key : EC_KEY) : Int
  fun ec_key_get0_private_key = EC_KEY_get0_private_key(key : EC_KEY) : Bignum
  fun ec_key_get0_public_key = EC_KEY_get0_public_key(key : EC_KEY) : EcPoint
  fun ec_key_get0_group = EC_KEY_get0_group(key : EC_KEY) : EcGroup
  fun ec_key_set_private_key = EC_KEY_set_private_key(key : EC_KEY, prv : Bignum) : Int
  fun ec_key_set_public_key = EC_KEY_set_public_key(key : EC_KEY, pub : EcPoint) : Int
  fun ec_key_check_key = EC_KEY_check_key(key : EC_KEY) : Int

  fun ec_group_get_degree = EC_GROUP_get_degree(group : EcGroup) : Int
  fun ec_group_get_curve_name = EC_GROUP_get_curve_name(group : EcGroup) : Int

  fun ec_point_new = EC_POINT_new(group : EcGroup) : EcPoint
  fun ec_point_free = EC_POINT_free(point : EcPoint)
  fun ec_point_set_affine_coordinates = EC_POINT_set_affine_coordinates(group : EcGroup, point : EcPoint, x : Bignum, y : Bignum, ctx : BignumCtx) : Int
  fun ec_point_get_affine_coordinates = EC_POINT_get_affine_coordinates(group : EcGroup, point : EcPoint, x : Bignum, y : Bignum, ctx : BignumCtx) : Int

  fun bn_new = BN_new : Bignum
  fun bn_free = BN_free(bn : Bignum)
  fun bn_bin2bn = BN_bin2bn(s : UInt8*, len : Int, ret : Bignum) : Bignum
  fun bn_bn2bin = BN_bn2bin(a : Bignum, to : UInt8*) : Int
  fun bn_bn2binpad = BN_bn2binpad(a : Bignum, to : UInt8*, tolen : Int) : Int
  fun bn_num_bits = BN_num_bits(a : Bignum) : Int

  fun bn_ctx_new = BN_CTX_new : BignumCtx
  fun bn_ctx_free = BN_CTX_free(ctx : BignumCtx)

  fun evp_pkey_new = EVP_PKEY_new : EvpPKey
  fun evp_pkey_free = EVP_PKEY_free(pkey : EvpPKey)
  fun evp_pkey_set1_ec_key = EVP_PKEY_set1_EC_KEY(pkey : EvpPKey, key : EC_KEY) : Int

  fun evp_pkey_ctx_new = EVP_PKEY_CTX_new(pkey : EvpPKey, e : Void*) : EvpPkeyCtx
  fun evp_pkey_ctx_free = EVP_PKEY_CTX_free(ctx : EvpPkeyCtx)

  fun evp_pkey_derive_init = EVP_PKEY_derive_init(ctx : EvpPkeyCtx) : Int
  fun evp_pkey_derive_set_peer = EVP_PKEY_derive_set_peer(ctx : EvpPkeyCtx, peer : EvpPKey) : Int
  fun evp_pkey_derive = EVP_PKEY_derive(ctx : EvpPkeyCtx, key : UInt8*, keylen : LibC::SizeT*) : Int

  fun evp_digestsigninit = EVP_DigestSignInit(ctx : EVP_MD_CTX, pctx : Void*, type : EVP_MD, e : Void*, pkey : EvpPKey) : Int
  fun evp_digestsign = EVP_DigestSign(ctx : EVP_MD_CTX, sigret : UInt8*, siglen : LibC::SizeT*, tbs : UInt8*, tbslen : LibC::SizeT) : Int
  fun evp_digestverifyinit = EVP_DigestVerifyInit(ctx : EVP_MD_CTX, pctx : Void*, type : EVP_MD, e : Void*, pkey : EvpPKey) : Int
  fun evp_digestverify = EVP_DigestVerify(ctx : EVP_MD_CTX, sigret : UInt8*, siglen : LibC::SizeT, tbs : UInt8*, tbslen : LibC::SizeT) : Int

  # RSA keys are built through the EVP-level DER entry points rather than
  # the low-level `RSA_new` / `RSA_set0_key` family, which OpenSSL 3
  # deprecated. `JWK::RSAKey` serialises its JWK members into
  # SubjectPublicKeyInfo or PKCS#8 and hands the result to these.
  #
  # Both `d2i_*` functions advance the pointer they are given, so callers
  # must pass a pointer to a throwaway copy.
  fun d2i_pubkey = d2i_PUBKEY(a : EvpPKey*, pp : UInt8**, length : Long) : EvpPKey
  fun d2i_autoprivatekey = d2i_AutoPrivateKey(a : EvpPKey*, pp : UInt8**, length : Long) : EvpPKey
  fun i2d_privatekey = i2d_PrivateKey(a : EvpPKey, pp : UInt8**) : Int
  # `EVP_RSA_gen` is a macro in OpenSSL 3, not a symbol; the real entry
  # point is this variadic one, called as (nil, nil, "RSA", size_t bits).
  fun evp_pkey_q_keygen = EVP_PKEY_Q_keygen(libctx : Void*, propq : UInt8*, type : UInt8*, ...) : EvpPKey

  fun evp_aes_256_gcm = EVP_aes_256_gcm : EVP_CIPHER

  fun evp_cipher_ctx_ctrl = EVP_CIPHER_CTX_ctrl(ctx : EVP_CIPHER_CTX, type : Int, arg : Int, ptr : Void*) : Int

  EVP_CTRL_GCM_SET_IVLEN =  0x9
  EVP_CTRL_GCM_GET_TAG   = 0x10
  EVP_CTRL_GCM_SET_TAG   = 0x11

  NID_X9_62_PRIME256V1 = 415
  NID_SECP384R1        = 715
  NID_SECP521R1        = 716
end
