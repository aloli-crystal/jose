module Jose
  # Minimal DER encoder/decoder.
  #
  # Only the handful of ASN.1 constructs JOSE needs are covered: INTEGER,
  # SEQUENCE, OCTET STRING, BIT STRING and NULL. Two places need them:
  #
  # * `JWS` converts ECDSA signatures between DER `SEQUENCE { r, s }` and the
  #   raw `r || s` concatenation JWS mandates;
  # * `JWK::RSAKey` builds SubjectPublicKeyInfo and PKCS#8 structures so RSA
  #   keys can be handed to OpenSSL through `d2i_PUBKEY` and
  #   `d2i_AutoPrivateKey` — the EVP-level entry points, which OpenSSL 3 has
  #   not deprecated, unlike the low-level `RSA_*` family.
  module DER
    class Error < Exception
    end

    TAG_INTEGER      = 0x02_u8
    TAG_BIT_STRING   = 0x03_u8
    TAG_OCTET_STRING = 0x04_u8
    TAG_NULL         = 0x05_u8
    TAG_SEQUENCE     = 0x30_u8

    # ==== Encoding =======================================================

    # Encode an unsigned big-endian magnitude as a DER INTEGER.
    #
    # DER INTEGERs are signed two's complement, so a leading `0x00` is
    # prepended whenever the top bit would otherwise read as negative.
    def self.integer(magnitude : Bytes) : Bytes
      stripped = strip_leading_zeros(magnitude)
      needs_pad = !stripped.empty? && (stripped[0] & 0x80) != 0
      content_size = (stripped.empty? ? 1 : stripped.size) + (needs_pad ? 1 : 0)

      io = IO::Memory.new
      io.write_byte TAG_INTEGER
      write_length(io, content_size)
      if stripped.empty?
        io.write_byte 0x00_u8
      else
        io.write_byte 0x00_u8 if needs_pad
        io.write stripped
      end
      io.to_slice.dup
    end

    def self.integer(value : Int32) : Bytes
      return integer(Bytes[0]) if value == 0
      raise Error.new("negative integers are not supported") if value < 0

      bytes = [] of UInt8
      v = value
      while v > 0
        bytes.unshift((v & 0xff).to_u8)
        v >>= 8
      end
      integer(Bytes.new(bytes.size) { |i| bytes[i] })
    end

    def self.sequence(payload : Bytes) : Bytes
      tagged(TAG_SEQUENCE, payload)
    end

    def self.octet_string(payload : Bytes) : Bytes
      tagged(TAG_OCTET_STRING, payload)
    end

    # BIT STRING with no unused trailing bits — the only form JOSE needs.
    def self.bit_string(payload : Bytes) : Bytes
      body = Bytes.new(payload.size + 1)
      body[0] = 0x00_u8
      payload.copy_to(body[1, payload.size])
      tagged(TAG_BIT_STRING, body)
    end

    def self.null : Bytes
      Bytes[TAG_NULL, 0x00]
    end

    def self.concat(*parts : Bytes) : Bytes
      total = parts.sum(&.size)
      result = Bytes.new(total)
      offset = 0
      parts.each do |part|
        part.copy_to(result[offset, part.size])
        offset += part.size
      end
      result
    end

    private def self.tagged(tag : UInt8, payload : Bytes) : Bytes
      io = IO::Memory.new
      io.write_byte tag
      write_length(io, payload.size)
      io.write payload
      io.to_slice.dup
    end

    def self.write_length(io : IO, len : Int32) : Nil
      if len < 0x80
        io.write_byte len.to_u8
      elsif len < 0x100
        io.write_byte 0x81_u8
        io.write_byte len.to_u8
      elsif len < 0x10000
        io.write_byte 0x82_u8
        io.write_byte ((len >> 8) & 0xff).to_u8
        io.write_byte (len & 0xff).to_u8
      elsif len < 0x1000000
        io.write_byte 0x83_u8
        io.write_byte ((len >> 16) & 0xff).to_u8
        io.write_byte ((len >> 8) & 0xff).to_u8
        io.write_byte (len & 0xff).to_u8
      else
        raise Error.new("DER length too large: #{len}")
      end
    end

    # ==== Decoding =======================================================

    # Cursor over a DER buffer.
    class Reader
      def initialize(@io : IO::Memory)
      end

      def self.new(bytes : Bytes)
        new(IO::Memory.new(bytes))
      end

      # Enter a SEQUENCE and return a reader scoped to its contents.
      def read_sequence : Reader
        Reader.new(read_tagged(TAG_SEQUENCE))
      end

      def read_octet_string : Bytes
        read_tagged(TAG_OCTET_STRING)
      end

      # Read a BIT STRING, rejecting any with unused trailing bits.
      def read_bit_string : Bytes
        body = read_tagged(TAG_BIT_STRING)
        raise Error.new("DER: empty BIT STRING") if body.empty?
        raise Error.new("DER: unused bits in BIT STRING are not supported") unless body[0] == 0x00_u8
        body[1, body.size - 1]
      end

      # Read an INTEGER and return it as an unsigned big-endian magnitude.
      def read_integer : Bytes
        DER.strip_leading_zeros(read_tagged(TAG_INTEGER))
      end

      def read_tagged(expected : UInt8) : Bytes
        tag = @io.read_byte || raise(Error.new("DER: truncated, expected tag 0x#{expected.to_s(16)}"))
        unless tag == expected
          raise Error.new("DER: expected tag 0x#{expected.to_s(16)}, got 0x#{tag.to_s(16)}")
        end
        len = read_length
        buf = Bytes.new(len)
        @io.read_fully(buf)
        buf
      end

      def skip(expected : UInt8) : Nil
        read_tagged(expected)
      end

      def at_end? : Bool
        @io.pos >= @io.size
      end

      private def read_length : Int32
        first = @io.read_byte || raise(Error.new("DER: truncated length"))
        return first.to_i32 if first < 0x80

        count = (first & 0x7f).to_i32
        raise Error.new("DER: indefinite length not allowed") if count == 0
        raise Error.new("DER: length field too long") if count > 4

        result = 0
        count.times do
          byte = @io.read_byte || raise(Error.new("DER: truncated length"))
          result = (result << 8) | byte.to_i32
        end
        raise Error.new("DER: negative length") if result < 0
        result
      end
    end

    # ==== Helpers ========================================================

    def self.strip_leading_zeros(bytes : Bytes) : Bytes
      i = 0
      while i < bytes.size - 1 && bytes[i] == 0
        i += 1
      end
      bytes[i, bytes.size - i]
    end

    def self.pad_left(bytes : Bytes, target_len : Int32) : Bytes
      raise Error.new("integer is #{bytes.size} bytes, does not fit in #{target_len}") if bytes.size > target_len
      padded = Bytes.new(target_len)
      bytes.copy_to(padded[target_len - bytes.size, bytes.size])
      padded
    end
  end
end
