require "base64"

module Jose
  module Utils
    extend self

    def base64url_encode(bytes : Bytes) : String
      Base64.urlsafe_encode(bytes, padding: false)
    end

    def base64url_encode(string : String) : String
      base64url_encode(string.to_slice)
    end

    def base64url_decode(encoded : String) : Bytes
      pad = (4 - encoded.bytesize % 4) % 4
      Base64.decode(encoded + "=" * pad)
    end
  end
end
