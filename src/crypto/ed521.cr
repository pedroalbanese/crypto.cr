# src/crypto/ed521.cr

require "big"
require "random/secure"

module Crypto
  module ED521
    extend self
    
    include Crypto::Constants
    include Crypto::Utils

    def on_curve?(x : BigInt, y : BigInt) : Bool
      x2 = (x * x) % ED521_P
      y2 = (y * y) % ED521_P
      left = (x2 + y2) % ED521_P
      
      d_pos = ED521_D < 0 ? ED521_D + ED521_P : ED521_D
      right = (1 + (d_pos * x2 * y2) % ED521_P) % ED521_P
      
      left == right
    end
    
    def add(x1 : BigInt, y1 : BigInt, x2 : BigInt, y2 : BigInt) : Tuple(BigInt, BigInt)
      if x1 == 0 && y1 == 1
        return {x2, y2}
      end
      if x2 == 0 && y2 == 1
        return {x1, y1}
      end
      
      x1y2 = (x1 * y2) % ED521_P
      y1x2 = (y1 * x2) % ED521_P
      numerator_x = (x1y2 + y1x2) % ED521_P
      
      y1y2 = (y1 * y2) % ED521_P
      x1x2 = (x1 * x2) % ED521_P
      numerator_y = (y1y2 - x1x2) % ED521_P
      
      d_pos = ED521_D < 0 ? ED521_D + ED521_P : ED521_D
      dx1x2y1y2 = (d_pos * ((x1x2 * y1y2) % ED521_P)) % ED521_P
      
      denominator_x = (1 + dx1x2y1y2) % ED521_P
      denominator_y = (1 - dx1x2y1y2) % ED521_P
      
      inv_den_x = mod_inverse(denominator_x, ED521_P)
      inv_den_y = mod_inverse(denominator_y, ED521_P)
      
      x3 = (numerator_x * inv_den_x) % ED521_P
      y3 = (numerator_y * inv_den_y) % ED521_P
      
      {x3, y3}
    end
    
    def double(x : BigInt, y : BigInt) : Tuple(BigInt, BigInt)
      add(x, y, x, y)
    end
    
    def scalar_mult(x : BigInt, y : BigInt, k_bytes : Bytes) : Tuple(BigInt, BigInt)
      scalar = bytes_to_little_int(k_bytes) % ED521_N
      
      result_x = BigInt.new(0)
      result_y = BigInt.new(1)
      temp_x = x
      temp_y = y
      
      while scalar > 0
        if scalar.odd?
          result_x, result_y = add(result_x, result_y, temp_x, temp_y)
        end
        temp_x, temp_y = double(temp_x, temp_y)
        scalar >>= 1
      end
      
      {result_x, result_y}
    end
    
    def scalar_base_mult(k_bytes : Bytes) : Tuple(BigInt, BigInt)
      scalar_mult(ED521_GX, ED521_GY, k_bytes)
    end

    def generate_private_key : BigInt
      loop do
        priv_bytes = Random::Secure.random_bytes(ED521_BYTE_LEN)
        a = bytes_to_little_int(priv_bytes)
        return a if a < ED521_N
      end
    end

    def get_public_key(private_key : BigInt) : Tuple(BigInt, BigInt)
      priv_bytes = little_int_to_bytes(private_key, ED521_BYTE_LEN)
      scalar_base_mult(priv_bytes)
    end

    def compress_point(x : BigInt, y : BigInt) : Bytes
      y_bytes = little_int_to_bytes(y, ED521_BYTE_LEN)
      x_lsb = (x & 1).to_u8
      y_bytes[ED521_BYTE_LEN - 1] |= (x_lsb << 7)
      y_bytes
    end

    def decompress_point(data : Bytes) : Tuple(BigInt?, BigInt?)
      return {nil, nil} if data.size != ED521_BYTE_LEN
      
      last_byte = data[ED521_BYTE_LEN - 1]
      sign_bit = (last_byte >> 7) & 1
      
      y_bytes = data.dup
      y_bytes[ED521_BYTE_LEN - 1] = last_byte & 0x7F
      y = bytes_to_little_int(y_bytes)
      
      return {nil, nil} if y >= ED521_P
      
      y2 = (y * y) % ED521_P
      
      numerator = (1 - y2) % ED521_P
      
      d_pos = ED521_D < 0 ? ED521_D + ED521_P : ED521_D
      denominator = (1 - (d_pos * y2) % ED521_P) % ED521_P
      
      inv_den = mod_inverse(denominator, ED521_P)
      return {nil, nil} if inv_den == 0
      
      x2 = (numerator * inv_den) % ED521_P
      
      exp = (ED521_P + 1) // 4
      x = mod_pow(x2, exp, ED521_P)
      
      x2_check = (x * x) % ED521_P
      if x2_check != x2
        x = (-x) % ED521_P
        x2_check = (x * x) % ED521_P
        return {nil, nil} if x2_check != x2
      end
      
      x_lsb = (x & 1).to_u8
      if x_lsb != sign_bit
        x = (-x) % ED521_P
      end
      
      return {nil, nil} unless on_curve?(x, y)
      
      {x, y}
    end

    private def dom5(phflag : UInt8, context : Bytes) : Bytes
      raise "context too long for dom5" if context.size > 255
      
      prefix = "SigEd521".to_slice
      len_byte = Bytes[context.size.to_u8]
      
      prefix + Bytes[phflag] + len_byte + context
    end

    private def hash_e521(phflag : UInt8, context : Bytes, x : Bytes) : Bytes
      dom = dom5(phflag, context)
      input = dom + x
      Crypto::SHA3.shake256(input, 132)
    end

    def sign(private_key : BigInt, message : Bytes) : Bytes
      byte_len = ED521_BYTE_LEN
      
      prefix = hash_e521(0x00_u8, Bytes.empty, little_int_to_bytes(private_key, byte_len))
      
      r_bytes = hash_e521(0x00_u8, Bytes.empty, prefix + message)
      r = bytes_to_little_int(r_bytes[0, byte_len]) % ED521_N
      
      rx, ry = scalar_base_mult(little_int_to_bytes(r, byte_len))
      r_compressed = compress_point(rx, ry)
      
      pub_x, pub_y = get_public_key(private_key)
      a_compressed = compress_point(pub_x, pub_y)
      
      hram_input = r_compressed + a_compressed + message
      hram_hash = hash_e521(0x00_u8, Bytes.empty, hram_input)
      h = bytes_to_little_int(hram_hash[0, byte_len]) % ED521_N
      
      s = (r + (h * private_key) % ED521_N) % ED521_N
      
      s_bytes = little_int_to_bytes(s, byte_len)
      r_compressed + s_bytes
    end

    def verify(public_x : BigInt, public_y : BigInt, message : Bytes, signature : Bytes) : Bool
      byte_len = ED521_BYTE_LEN
      
      return false if signature.size != 2 * byte_len
      
      r_compressed = signature[0, byte_len]
      s_bytes = signature[byte_len, byte_len]
      
      rx, ry = decompress_point(r_compressed)
      return false if rx.nil? || ry.nil?
      
      s = bytes_to_little_int(s_bytes)
      return false if s >= ED521_N
      
      a_compressed = compress_point(public_x, public_y)
      
      hram_input = r_compressed + a_compressed + message
      hram_hash = hash_e521(0x00_u8, Bytes.empty, hram_input)
      h = bytes_to_little_int(hram_hash[0, byte_len]) % ED521_N
      
      sg_x, sg_y = scalar_base_mult(little_int_to_bytes(s, byte_len))
      
      ha_x, ha_y = scalar_mult(public_x, public_y, little_int_to_bytes(h, byte_len))
      
      rha_x, rha_y = add(rx, ry, ha_x, ha_y)
      
      constant_time_compare(little_int_to_bytes(sg_x, byte_len), little_int_to_bytes(rha_x, byte_len)) &&
      constant_time_compare(little_int_to_bytes(sg_y, byte_len), little_int_to_bytes(rha_y, byte_len))
    end

    def prove_knowledge(private_key : BigInt) : Bytes
      byte_len = ED521_BYTE_LEN
      
      r = loop do
        r_bytes = Random::Secure.random_bytes(byte_len)
        r_val = bytes_to_little_int(r_bytes)
        break r_val if r_val < ED521_N
      end
      
      rx, ry = scalar_base_mult(little_int_to_bytes(r, byte_len))
      r_comp = compress_point(rx, ry)
      
      pub_x, pub_y = get_public_key(private_key)
      a_comp = compress_point(pub_x, pub_y)
      
      input_data = r_comp + a_comp
      c_bytes = hash_e521(0x00_u8, Bytes.empty, input_data)
      c = bytes_to_little_int(c_bytes[0, byte_len]) % ED521_N
      
      s = (r + (c * private_key) % ED521_N) % ED521_N
      
      s_bytes = little_int_to_bytes(s, byte_len)
      r_comp + s_bytes
    end

    def verify_knowledge(public_x : BigInt, public_y : BigInt, proof : Bytes) : Bool
      byte_len = ED521_BYTE_LEN
      
      return false if proof.size != 2 * byte_len
      
      r_comp = proof[0, byte_len]
      s_bytes = proof[byte_len, byte_len]
      
      rx, ry = decompress_point(r_comp)
      return false if rx.nil? || ry.nil?
      
      s = bytes_to_little_int(s_bytes)
      
      a_comp = compress_point(public_x, public_y)
      input_data = r_comp + a_comp
      c_bytes = hash_e521(0x00_u8, Bytes.empty, input_data)
      c = bytes_to_little_int(c_bytes[0, byte_len]) % ED521_N
      
      sg_x, sg_y = scalar_base_mult(little_int_to_bytes(s, byte_len))
      ca_x, ca_y = scalar_mult(public_x, public_y, little_int_to_bytes(c, byte_len))
      rca_x, rca_y = add(rx, ry, ca_x, ca_y)
      
      constant_time_compare(little_int_to_bytes(sg_x, byte_len), little_int_to_bytes(rca_x, byte_len)) &&
      constant_time_compare(little_int_to_bytes(sg_y, byte_len), little_int_to_bytes(rca_y, byte_len))
    end
  end
end
