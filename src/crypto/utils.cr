# src/crypto/utils.cr

module Crypto
  module Utils
    extend self

    def hex_to_bytes(hex : String) : Bytes
      hex = hex.gsub(/\s+/, "")
      hex = "0" + hex if hex.size.odd?
      bytes = Bytes.new(hex.size // 2)
      hex.size.times do |i|
        next if i.even?
        byte = hex[i-1, 2].to_u8(16)
        bytes[(i-1)//2] = byte
      end
      bytes
    rescue
      raise ArgumentError.new("Invalid hex string: #{hex}")
    end

    def bytes_to_hex(bytes : Bytes) : String
      String.build { |str| bytes.each { |b| str << b.to_s(16).rjust(2, '0') } }
    end

    def constant_time_compare(a : Bytes, b : Bytes) : Bool
      return false if a.size != b.size
      result = 0
      a.size.times { |i| result |= a[i] ^ b[i] }
      result == 0
    end

    def xor_bytes(a : Bytes, b : Bytes) : Bytes
      len = Math.min(a.size, b.size)
      Bytes.new(len).tap do |result|
        len.times { |i| result[i] = (a[i] ^ b[i]).to_u8 }
      end
    end

    def little_int_to_bytes(n : BigInt, length : Int32) : Bytes
      hex = n.to_s(16)
      hex = hex.rjust(hex.size + (hex.size.odd? ? 1 : 0), '0')
      bytes_be = Bytes.new(hex.size // 2) { |i| hex[2*i, 2].to_u8(16) }
      
      if bytes_be.size < length
        padding = Bytes.new(length - bytes_be.size, 0_u8)
        bytes_be = padding + bytes_be
      end
      
      bytes_le = Bytes.new(length, 0_u8)
      length.times { |i| bytes_le[i] = bytes_be[length - 1 - i] }
      bytes_le
    end

    def bytes_to_little_int(bytes : Bytes) : BigInt
      result = BigInt.new(0)
      bytes.size.times do |i|
        result |= BigInt.new(bytes[i]) << (i * 8)
      end
      result
    end

    def mod_inverse(a : BigInt, m : BigInt) : BigInt
      m0 = m
      x0 = BigInt.new(0)
      x1 = BigInt.new(1)
      
      return BigInt.new(0) if m == 1
      
      a = a % m
      while a > 1
        q = a // m
        t = m
        
        m = a % m
        a = t
        t = x0
        
        x0 = x1 - q * x0
        x1 = t
      end
      
      x1 < 0 ? x1 + m0 : x1
    end

    def mod_pow(base : BigInt, exp : BigInt, mod : BigInt) : BigInt
      result = BigInt.new(1)
      b = base % mod
      e = exp
      while e > 0
        if e.odd?
          result = (result * b) % mod
        end
        b = (b * b) % mod
        e >>= 1
      end
      result
    end
  end
end
