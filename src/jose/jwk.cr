require "json"
require "openssl"
require "openssl/digest"
require "./openssl_ext"
require "./utils"

module Jose
  module JWK
    class Error < Exception
    end

    class UnsupportedAlgorithmError < Error
    end

    class InvalidKeyError < Error
    end

    enum Curve
      P256
      P384
      P521

      def self.from_jwk_name(name : String) : Curve
        case name
        when "P-256" then P256
        when "P-384" then P384
        when "P-521" then P521
        else
          raise UnsupportedAlgorithmError.new("unsupported curve: #{name}")
        end
      end

      def jwk_name : String
        case self
        in P256 then "P-256"
        in P384 then "P-384"
        in P521 then "P-521"
        end
      end

      def nid : LibCrypto::Int
        case self
        in P256 then LibCrypto::NID_X9_62_PRIME256V1.to_i
        in P384 then LibCrypto::NID_SECP384R1.to_i
        in P521 then LibCrypto::NID_SECP521R1.to_i
        end
      end

      def coordinate_octet_length : Int32
        case self
        in P256 then 32
        in P384 then 48
        in P521 then 66
        end
      end
    end

    # An Elliptic Curve JWK as per RFC 7517 §4.2 / RFC 7518 §6.2.
    #
    # Always carries the public coordinates `x` and `y`. When `d` is
    # present, this is a private key.
    class ECKey
      getter curve : Curve
      getter x : Bytes
      getter y : Bytes
      getter d : Bytes?
      getter kid : String?
      getter use : String?
      getter alg : String?

      def initialize(@curve : Curve, @x : Bytes, @y : Bytes, @d : Bytes? = nil,
                     @kid : String? = nil, @use : String? = nil, @alg : String? = nil)
        expected_len = @curve.coordinate_octet_length
        raise InvalidKeyError.new("x has wrong length") if @x.size != expected_len
        raise InvalidKeyError.new("y has wrong length") if @y.size != expected_len
        if priv = @d
          raise InvalidKeyError.new("d has wrong length") if priv.size != expected_len
        end
      end

      def private? : Bool
        !@d.nil?
      end

      def public_key : ECKey
        ECKey.new(@curve, @x, @y, kid: @kid, use: @use, alg: @alg)
      end

      # Construct an ECKey by generating a fresh keypair.
      def self.generate(curve : Curve) : ECKey
        ec_key = LibCrypto.ec_key_new_by_curve_name(curve.nid)
        raise InvalidKeyError.new("EC_KEY_new_by_curve_name failed") if ec_key.null?
        begin
          if LibCrypto.ec_key_generate_key(ec_key) != 1
            raise InvalidKeyError.new("EC_KEY_generate_key failed")
          end
          from_ec_key(ec_key, curve)
        ensure
          LibCrypto.ec_key_free(ec_key)
        end
      end

      def self.from_json(json : String) : ECKey
        h = Hash(String, JSON::Any).from_json(json)
        from_jwk_hash(h)
      end

      def self.from_jwk_hash(h : Hash(String, JSON::Any)) : ECKey
        kty = h["kty"]?.try(&.as_s)
        raise UnsupportedAlgorithmError.new("kty must be \"EC\"") unless kty == "EC"

        crv_name = h["crv"]?.try(&.as_s) ||
                   raise(InvalidKeyError.new("missing crv"))
        x_b64 = h["x"]?.try(&.as_s) || raise(InvalidKeyError.new("missing x"))
        y_b64 = h["y"]?.try(&.as_s) || raise(InvalidKeyError.new("missing y"))
        d_b64 = h["d"]?.try(&.as_s)

        curve = Curve.from_jwk_name(crv_name)
        x = Utils.base64url_decode(x_b64)
        y = Utils.base64url_decode(y_b64)
        d = d_b64.try { |s| Utils.base64url_decode(s) }

        ECKey.new(curve, x, y, d,
          kid: h["kid"]?.try(&.as_s),
          use: h["use"]?.try(&.as_s),
          alg: h["alg"]?.try(&.as_s))
      end

      # Serialize to a JWK JSON object.
      # When `include_private` is false, `d` is stripped.
      def to_jwk_hash(include_private : Bool = false) : Hash(String, String)
        h = {} of String => String
        h["kty"] = "EC"
        h["crv"] = @curve.jwk_name
        h["x"] = Utils.base64url_encode(@x)
        h["y"] = Utils.base64url_encode(@y)
        if include_private && (priv = @d)
          h["d"] = Utils.base64url_encode(priv)
        end
        h["kid"] = @kid.not_nil! if @kid
        h["use"] = @use.not_nil! if @use
        h["alg"] = @alg.not_nil! if @alg
        h
      end

      def to_json(include_private : Bool = false) : String
        to_jwk_hash(include_private).to_json
      end

      # RFC 7638 — Compute the canonical JWK Thumbprint (SHA-256).
      # Only the required members are hashed, in lexical order.
      def thumbprint : Bytes
        canonical = String.build do |s|
          s << '{'
          s << %("crv":"#{@curve.jwk_name}",)
          s << %("kty":"EC",)
          s << %("x":"#{Utils.base64url_encode(@x)}",)
          s << %("y":"#{Utils.base64url_encode(@y)}")
          s << '}'
        end
        digest = OpenSSL::Digest.new("SHA256")
        digest.update(canonical.to_slice)
        digest.final
      end

      def thumbprint_base64url : String
        Utils.base64url_encode(thumbprint)
      end

      # ==== OpenSSL bridge =================================================

      # Build a fresh EC_KEY from this JWK. Caller owns and must free.
      protected def to_ec_key : LibCrypto::EC_KEY
        ec_key = LibCrypto.ec_key_new_by_curve_name(@curve.nid)
        raise InvalidKeyError.new("EC_KEY_new_by_curve_name failed") if ec_key.null?

        bn_ctx = LibCrypto.bn_ctx_new
        bn_x = LibCrypto.bn_bin2bn(@x.to_unsafe, @x.size, Pointer(Void).null.as(LibCrypto::Bignum))
        bn_y = LibCrypto.bn_bin2bn(@y.to_unsafe, @y.size, Pointer(Void).null.as(LibCrypto::Bignum))
        group = LibCrypto.ec_key_get0_group(ec_key)
        point = LibCrypto.ec_point_new(group)

        begin
          if LibCrypto.ec_point_set_affine_coordinates(group, point, bn_x, bn_y, bn_ctx) != 1
            raise InvalidKeyError.new("EC_POINT_set_affine_coordinates failed")
          end
          if LibCrypto.ec_key_set_public_key(ec_key, point) != 1
            raise InvalidKeyError.new("EC_KEY_set_public_key failed")
          end
          if priv = @d
            bn_d = LibCrypto.bn_bin2bn(priv.to_unsafe, priv.size, Pointer(Void).null.as(LibCrypto::Bignum))
            begin
              if LibCrypto.ec_key_set_private_key(ec_key, bn_d) != 1
                raise InvalidKeyError.new("EC_KEY_set_private_key failed")
              end
            ensure
              LibCrypto.bn_free(bn_d)
            end
          end
          if LibCrypto.ec_key_check_key(ec_key) != 1
            raise InvalidKeyError.new("EC_KEY_check_key failed (invalid point)")
          end
          ec_key
        rescue ex
          LibCrypto.ec_key_free(ec_key)
          raise ex
        ensure
          LibCrypto.ec_point_free(point) unless point.null?
          LibCrypto.bn_free(bn_x) unless bn_x.null?
          LibCrypto.bn_free(bn_y) unless bn_y.null?
          LibCrypto.bn_ctx_free(bn_ctx) unless bn_ctx.null?
        end
      end

      # Wrap a fresh EVP_PKEY around this JWK. Caller owns and must free.
      protected def to_evp_pkey : LibCrypto::EvpPKey
        ec_key = to_ec_key
        pkey = LibCrypto.evp_pkey_new
        raise InvalidKeyError.new("EVP_PKEY_new failed") if pkey.null?
        if LibCrypto.evp_pkey_set1_ec_key(pkey, ec_key) != 1
          LibCrypto.evp_pkey_free(pkey)
          LibCrypto.ec_key_free(ec_key)
          raise InvalidKeyError.new("EVP_PKEY_set1_EC_KEY failed")
        end
        # set1 increments the EC_KEY ref count internally; we still own
        # our handle and must free it.
        LibCrypto.ec_key_free(ec_key)
        pkey
      end

      # Build an ECKey from an existing EC_KEY (does not take ownership).
      protected def self.from_ec_key(ec_key : LibCrypto::EC_KEY, curve : Curve) : ECKey
        group = LibCrypto.ec_key_get0_group(ec_key)
        point = LibCrypto.ec_key_get0_public_key(ec_key)

        bn_x = LibCrypto.bn_new
        bn_y = LibCrypto.bn_new
        bn_ctx = LibCrypto.bn_ctx_new

        begin
          if LibCrypto.ec_point_get_affine_coordinates(group, point, bn_x, bn_y, bn_ctx) != 1
            raise InvalidKeyError.new("EC_POINT_get_affine_coordinates failed")
          end

          coord_len = curve.coordinate_octet_length
          x_bytes = Bytes.new(coord_len)
          y_bytes = Bytes.new(coord_len)
          if LibCrypto.bn_bn2binpad(bn_x, x_bytes.to_unsafe, coord_len) != coord_len
            raise InvalidKeyError.new("BN_bn2binpad(x) failed")
          end
          if LibCrypto.bn_bn2binpad(bn_y, y_bytes.to_unsafe, coord_len) != coord_len
            raise InvalidKeyError.new("BN_bn2binpad(y) failed")
          end

          d_bytes : Bytes? = nil
          bn_d = LibCrypto.ec_key_get0_private_key(ec_key)
          unless bn_d.null?
            d_buf = Bytes.new(coord_len)
            if LibCrypto.bn_bn2binpad(bn_d, d_buf.to_unsafe, coord_len) != coord_len
              raise InvalidKeyError.new("BN_bn2binpad(d) failed")
            end
            d_bytes = d_buf
          end

          ECKey.new(curve, x_bytes, y_bytes, d_bytes)
        ensure
          LibCrypto.bn_free(bn_x)
          LibCrypto.bn_free(bn_y)
          LibCrypto.bn_ctx_free(bn_ctx)
        end
      end
    end
  end
end
