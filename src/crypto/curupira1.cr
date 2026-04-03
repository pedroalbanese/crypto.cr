# src/crypto/curupira1.cr

module Crypto::Curupira1
  extend self

  BLOCK_SIZE = 12

  class InvalidKeyError < Exception
    def initialize
      super("curupira1: invalid key length (must be 12, 18, or 24 bytes)")
    end
  end

  S_BOX_TABLE = [
    0xba, 0x54, 0x2f, 0x74, 0x53, 0xd3, 0xd2, 0x4d,
    0x50, 0xac, 0x8d, 0xbf, 0x70, 0x52, 0x9a, 0x4c,
    0xea, 0xd5, 0x97, 0xd1, 0x33, 0x51, 0x5b, 0xa6,
    0xde, 0x48, 0xa8, 0x99, 0xdb, 0x32, 0xb7, 0xfc,
    0xe3, 0x9e, 0x91, 0x9b, 0xe2, 0xbb, 0x41, 0x6e,
    0xa5, 0xcb, 0x6b, 0x95, 0xa1, 0xf3, 0xb1, 0x02,
    0xcc, 0xc4, 0x1d, 0x14, 0xc3, 0x63, 0xda, 0x5d,
    0x5f, 0xdc, 0x7d, 0xcd, 0x7f, 0x5a, 0x6c, 0x5c,
    0xf7, 0x26, 0xff, 0xed, 0xe8, 0x9d, 0x6f, 0x8e,
    0x19, 0xa0, 0xf0, 0x89, 0x0f, 0x07, 0xaf, 0xfb,
    0x08, 0x15, 0x0d, 0x04, 0x01, 0x64, 0xdf, 0x76,
    0x79, 0xdd, 0x3d, 0x16, 0x3f, 0x37, 0x6d, 0x38,
    0xb9, 0x73, 0xe9, 0x35, 0x55, 0x71, 0x7b, 0x8c,
    0x72, 0x88, 0xf6, 0x2a, 0x3e, 0x5e, 0x27, 0x46,
    0x0c, 0x65, 0x68, 0x61, 0x03, 0xc1, 0x57, 0xd6,
    0xd9, 0x58, 0xd8, 0x66, 0xd7, 0x3a, 0xc8, 0x3c,
    0xfa, 0x96, 0xa7, 0x98, 0xec, 0xb8, 0xc7, 0xae,
    0x69, 0x4b, 0xab, 0xa9, 0x67, 0x0a, 0x47, 0xf2,
    0xb5, 0x22, 0xe5, 0xee, 0xbe, 0x2b, 0x81, 0x12,
    0x83, 0x1b, 0x0e, 0x23, 0xf5, 0x45, 0x21, 0xce,
    0x49, 0x2c, 0xf9, 0xe6, 0xb6, 0x28, 0x17, 0x82,
    0x1a, 0x8b, 0xfe, 0x8a, 0x09, 0xc9, 0x87, 0x4e,
    0xe1, 0x2e, 0xe4, 0xe0, 0xeb, 0x90, 0xa4, 0x1e,
    0x85, 0x60, 0x00, 0x25, 0xf4, 0xf1, 0x94, 0x0b,
    0xe7, 0x75, 0xef, 0x34, 0x31, 0xd4, 0xd0, 0x86,
    0x7e, 0xad, 0xfd, 0x29, 0x30, 0x3b, 0x9f, 0xf8,
    0xc6, 0x13, 0x06, 0x05, 0xc5, 0x11, 0x77, 0x7c,
    0x7a, 0x78, 0x36, 0x1c, 0x39, 0x59, 0x18, 0x56,
    0xb3, 0xb0, 0x24, 0x20, 0xb2, 0x92, 0xa3, 0xc0,
    0x44, 0x62, 0x10, 0xb4, 0x84, 0x43, 0x93, 0xc2,
    0x4a, 0xbd, 0x8f, 0x2d, 0xbc, 0x9c, 0x6a, 0x40,
    0xcf, 0xa2, 0x80, 0x4f, 0x1f, 0xca, 0xaa, 0x42,
  ].map(&.to_u8)

  X_TIMES_TABLE = [
    0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E,
    0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
    0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E,
    0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
    0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E,
    0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
    0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E,
    0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
    0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E,
    0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
    0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE,
    0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
    0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE,
    0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
    0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE,
    0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
    0x4D, 0x4F, 0x49, 0x4B, 0x45, 0x47, 0x41, 0x43,
    0x5D, 0x5F, 0x59, 0x5B, 0x55, 0x57, 0x51, 0x53,
    0x6D, 0x6F, 0x69, 0x6B, 0x65, 0x67, 0x61, 0x63,
    0x7D, 0x7F, 0x79, 0x7B, 0x75, 0x77, 0x71, 0x73,
    0x0D, 0x0F, 0x09, 0x0B, 0x05, 0x07, 0x01, 0x03,
    0x1D, 0x1F, 0x19, 0x1B, 0x15, 0x17, 0x11, 0x13,
    0x2D, 0x2F, 0x29, 0x2B, 0x25, 0x27, 0x21, 0x23,
    0x3D, 0x3F, 0x39, 0x3B, 0x35, 0x37, 0x31, 0x33,
    0xCD, 0xCF, 0xC9, 0xCB, 0xC5, 0xC7, 0xC1, 0xC3,
    0xDD, 0xDF, 0xD9, 0xDB, 0xD5, 0xD7, 0xD1, 0xD3,
    0xED, 0xEF, 0xE9, 0xEB, 0xE5, 0xE7, 0xE1, 0xE3,
    0xFD, 0xFF, 0xF9, 0xFB, 0xF5, 0xF7, 0xF1, 0xF3,
    0x8D, 0x8F, 0x89, 0x8B, 0x85, 0x87, 0x81, 0x83,
    0x9D, 0x9F, 0x99, 0x9B, 0x95, 0x97, 0x91, 0x93,
    0xAD, 0xAF, 0xA9, 0xAB, 0xA5, 0xA7, 0xA1, 0xA3,
    0xBD, 0xBF, 0xB9, 0xBB, 0xB5, 0xB7, 0xB1, 0xB3,
  ].map(&.to_u8)

  def self.s_box(v : UInt8) : UInt8
    S_BOX_TABLE[v]
  end

  def self.x_times(v : UInt8) : UInt8
    X_TIMES_TABLE[v]
  end

  class Cipher
    getter block_size : Int32
    getter key_bits : Int32
    getter rounds : Int32
    getter t : Int32
    getter encryption_round_keys : Array(Bytes)
    getter decryption_round_keys : Array(Bytes)

    def initialize(key : Bytes)
      @block_size = BLOCK_SIZE
      
      if key.size != 12 && key.size != 18 && key.size != 24
        raise InvalidKeyError.new
      end

      @key_bits = key.size * 8
      
      @rounds = case key.size
                when 12 then 10
                when 18 then 14
                else        18
                end
      
      @t = @key_bits // 48
      
      @encryption_round_keys = Array(Bytes).new(@rounds + 1)
      @decryption_round_keys = Array(Bytes).new(@rounds + 1)
      
      expand_key(key)
    end

    def encrypt(dst : Bytes, src : Bytes) : Nil
      raise "curupira1: input not full block" if src.size < @block_size
      raise "curupira1: output not full block" if dst.size < @block_size

      process_block(dst, src, @encryption_round_keys)
    end

    def decrypt(dst : Bytes, src : Bytes) : Nil
      raise "curupira1: input not full block" if src.size < @block_size
      raise "curupira1: output not full block" if dst.size < @block_size

      process_block(dst, src, @decryption_round_keys)
    end

    def sct(dst : Bytes, src : Bytes) : Nil
      raise "curupira1: input not full block" if src.size < @block_size
      raise "curupira1: output not full block" if dst.size < @block_size

      tmp = perform_unkeyed_round(src)
      3.times do
        tmp = perform_unkeyed_round(tmp)
      end

      tmp.copy_to(dst)
    end

    private def process_block(dst : Bytes, src : Bytes, round_keys : Array(Bytes)) : Nil
      block = src.dup

      block = perform_whitening_round(block, round_keys[0])

      (1...@rounds).each do |r|
        block = perform_round(block, round_keys[r])
      end

      block = perform_last_round(block, round_keys[@rounds])

      block.copy_to(dst)
    end

    private def expand_key(key : Bytes) : Nil
      kr = key.dup
      krk = select_round_key(kr)
      @encryption_round_keys << krk

      (1..@rounds).each do |r|
        kr = calculate_next_subkey(kr, r)
        krk = select_round_key(kr)
        @encryption_round_keys << krk
      end

      (0..@rounds).each do |r|
        @decryption_round_keys << Bytes.new(@block_size, 0)
      end

      @decryption_round_keys[0] = @encryption_round_keys[@rounds].dup
      @decryption_round_keys[@rounds] = @encryption_round_keys[0].dup

      (1...@rounds).each do |r|
        @decryption_round_keys[r] = apply_linear_diffusion_layer(@encryption_round_keys[@rounds - r])
      end
    end

    private def calculate_next_subkey(kr : Bytes, subkey_rank : Int32) : Bytes
      result = apply_linear_diffusion(
        apply_cyclic_shift(
          apply_constant_addition(kr, subkey_rank),
          @t
        ),
        @t
      )
      
      Bytes.new(result.size).tap do |bytes|
        result.each_with_index { |v, i| bytes[i] = v }
      end
    end

    private def apply_constant_addition(kr : Bytes, subkey_rank : Int32) : Array(UInt8)
      q = calculate_schedule_constant(subkey_rank)
      result = Array(UInt8).new(3 * 2 * @t, 0_u8)
      
      (0...3).each do |i|
        (0...(2 * @t)).each do |j|
          result[i + 3*j] = (kr[i + 3*j] ^ q[i + 3*j]).to_u8
        end
      end
      
      result
    end

    private def calculate_schedule_constant(s : Int32) : Array(UInt8)
      size = 3 * 2 * @t
      q = Array(UInt8).new(size, 0_u8)

      if s == 0
        return q
      end

      (0...(2 * @t)).each do |j|
        q[3*j] = Curupira1.s_box((2 * @t * (s - 1) + j).to_u8!)
      end

      q
    end

    private def apply_cyclic_shift(a : Array(UInt8), t : Int32) : Array(UInt8)
      size = 3 * 2 * t
      b = Array(UInt8).new(size, 0_u8)

      (0...(2 * t)).each do |j|
        b[3*j] = a[3*j]
        b[1 + 3*j] = a[1 + 3 * ((j + 1) % (2 * t))]
        
        if j > 0
          b[2 + 3*j] = a[2 + 3 * ((j - 1) % (2 * t))]
        else
          b[2] = a[2 + 3 * (2 * t - 1)]
        end
      end

      b
    end

    private def apply_linear_diffusion(a : Array(UInt8), t : Int32) : Array(UInt8)
      size = 3 * 2 * t
      b = Array(UInt8).new(size, 0_u8)

      (0...(2 * t)).each do |j|
        e_times_a(a, j, b, true)
      end

      b
    end

    private def select_round_key(kr : Bytes) : Bytes
      result = Bytes.new(12, 0_u8)

      (0...4).each do |j|
        result[3*j] = Curupira1.s_box(kr[3*j])
      end

      (1...3).each do |i|
        (0...4).each do |j|
          result[i + 3*j] = kr[i + 3*j]
        end
      end

      result
    end

    private def apply_non_linear_layer(a : Bytes) : Bytes
      Bytes.new(12).tap do |b|
        12.times { |i| b[i] = Curupira1.s_box(a[i]) }
      end
    end

    private def apply_permutation_layer(a : Bytes) : Bytes
      Bytes.new(12).tap do |b|
        (0...3).each do |i|
          (0...4).each do |j|
            b[i + 3*j] = a[i + 3*(i ^ j)]
          end
        end
      end
    end

    private def apply_linear_diffusion_layer(a : Bytes) : Bytes
      Bytes.new(12).tap do |b|
        (0...4).each do |j|
          d_times_a(a, j, b)
        end
      end
    end

    private def apply_key_addition(a : Bytes, kr : Bytes) : Bytes
      Bytes.new(12).tap do |b|
        (0...3).each do |i|
          (0...4).each do |j|
            b[i + 3*j] = (a[i + 3*j] ^ kr[i + 3*j]).to_u8
          end
        end
      end
    end

    private def perform_whitening_round(a : Bytes, k0 : Bytes) : Bytes
      apply_key_addition(a, k0)
    end

    private def perform_last_round(a : Bytes, kr : Bytes) : Bytes
      apply_key_addition(
        apply_permutation_layer(
          apply_non_linear_layer(a)
        ),
        kr
      )
    end

    private def perform_round(a : Bytes, kr : Bytes) : Bytes
      apply_key_addition(
        apply_linear_diffusion_layer(
          apply_permutation_layer(
            apply_non_linear_layer(a)
          )
        ),
        kr
      )
    end

    private def perform_unkeyed_round(a : Bytes) : Bytes
      apply_linear_diffusion_layer(
        apply_permutation_layer(
          apply_non_linear_layer(a)
        )
      )
    end

    private def d_times_a(a : Bytes, j : Int32, b : Bytes) : Nil
      d = 3 * j
      v = Curupira1.x_times((a[0 + d] ^ a[1 + d] ^ a[2 + d]).to_u8)
      w = Curupira1.x_times(v)

      b[0 + d] = (a[0 + d] ^ v).to_u8
      b[1 + d] = (a[1 + d] ^ w).to_u8
      b[2 + d] = (a[2 + d] ^ v ^ w).to_u8
    end

    private def e_times_a(a : Array(UInt8) | Bytes, j : Int32, b : Array(UInt8), e : Bool) : Nil
      d = 3 * j
      v = (a[0 + d] ^ a[1 + d] ^ a[2 + d]).to_u8

      if e
        v = c_times(v)
      else
        v = (c_times(v) ^ v).to_u8
      end

      b[0 + d] = (a[0 + d] ^ v).to_u8
      b[1 + d] = (a[1 + d] ^ v).to_u8
      b[2 + d] = (a[2 + d] ^ v).to_u8
    end

    private def c_times(u : UInt8) : UInt8
      Curupira1.x_times(
        Curupira1.x_times(
          Curupira1.x_times(
            Curupira1.x_times(u) ^ u
          ) ^ u
        )
      )
    end
  end

  C = 0x2A_u8

  class CBC
    @cipher : Cipher
    @iv : Bytes

    def initialize(@cipher, @iv)
      raise "IV must be #{@cipher.block_size} bytes" if @iv.size != @cipher.block_size
    end

    def encrypt(data : Bytes) : Bytes
      block_size = @cipher.block_size
      
      padding_len = block_size - (data.size % block_size)
      padding_len = block_size if padding_len == 0
      
      padded = Bytes.new(data.size + padding_len)
      data.size.times { |i| padded[i] = data[i] }
      (data.size...padded.size).each { |i| padded[i] = padding_len.to_u8 }
      
      result = Bytes.new(padded.size)
      prev = @iv.dup
      
      (0...padded.size).step(block_size) do |i|
        block = padded[i, block_size]
        
        xored = xor_bytes(block, prev)
        
        encrypted = Bytes.new(block_size)
        @cipher.encrypt(encrypted, xored)
        
        encrypted.size.times { |j| result[i + j] = encrypted[j] }
        
        prev = encrypted
      end
      
      result
    end

    def decrypt(data : Bytes) : Bytes
      block_size = @cipher.block_size
      
      raise "Data size must be multiple of block size" if data.size % block_size != 0
      
      result = Bytes.new(data.size)
      prev = @iv.dup
      
      (0...data.size).step(block_size) do |i|
        block = data[i, block_size]
        
        decrypted = Bytes.new(block_size)
        @cipher.decrypt(decrypted, block)
        
        plain = xor_bytes(decrypted, prev)
        
        plain.size.times { |j| result[i + j] = plain[j] }
        
        prev = block
      end
      
      padding_len = result[-1].to_i
      raise "Invalid padding" if padding_len < 1 || padding_len > block_size
      
      (result.size - padding_len...result.size).each do |i|
        raise "Invalid padding" if result[i] != padding_len
      end
      
      result[0, result.size - padding_len]
    end
  end
end

# Função auxiliar global para xor_bytes (se não existir)
def xor_bytes(a : Bytes, b : Bytes) : Bytes
  len = Math.min(a.size, b.size)
  Bytes.new(len).tap do |result|
    len.times { |i| result[i] = (a[i] ^ b[i]).to_u8 }
  end
end
