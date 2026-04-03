# src/crypto/md5.cr

module Crypto::MD5
  extend self

  private S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
  ]

  private K = [
    0xd76aa478_u32, 0xe8c7b756_u32, 0x242070db_u32, 0xc1bdceee_u32,
    0xf57c0faf_u32, 0x4787c62a_u32, 0xa8304613_u32, 0xfd469501_u32,
    0x698098d8_u32, 0x8b44f7af_u32, 0xffff5bb1_u32, 0x895cd7be_u32,
    0x6b901122_u32, 0xfd987193_u32, 0xa679438e_u32, 0x49b40821_u32,
    0xf61e2562_u32, 0xc040b340_u32, 0x265e5a51_u32, 0xe9b6c7aa_u32,
    0xd62f105d_u32, 0x02441453_u32, 0xd8a1e681_u32, 0xe7d3fbc8_u32,
    0x21e1cde6_u32, 0xc33707d6_u32, 0xf4d50d87_u32, 0x455a14ed_u32,
    0xa9e3e905_u32, 0xfcefa3f8_u32, 0x676f02d9_u32, 0x8d2a4c8a_u32,
    0xfffa3942_u32, 0x8771f681_u32, 0x6d9d6122_u32, 0xfde5380c_u32,
    0xa4beea44_u32, 0x4bdecfa9_u32, 0xf6bb4b60_u32, 0xbebfbc70_u32,
    0x289b7ec6_u32, 0xeaa127fa_u32, 0xd4ef3085_u32, 0x04881d05_u32,
    0xd9d4d039_u32, 0xe6db99e5_u32, 0x1fa27cf8_u32, 0xc4ac5665_u32,
    0xf4292244_u32, 0x432aff97_u32, 0xab9423a7_u32, 0xfc93a039_u32,
    0x655b59c3_u32, 0x8f0ccc92_u32, 0xffeff47d_u32, 0x85845dd1_u32,
    0x6fa87e4f_u32, 0xfe2ce6e0_u32, 0xa3014314_u32, 0x4e0811a1_u32,
    0xf7537e82_u32, 0xbd3af235_u32, 0x2ad7d2bb_u32, 0xeb86d391_u32
  ]

  private H0 = 0x67452301_u32
  private H1 = 0xefcdab89_u32
  private H2 = 0x98badcfe_u32
  private H3 = 0x10325476_u32

  private def rotate_left(x : UInt32, n : Int32) : UInt32
    (x << n) | (x >> (32 - n))
  end

  private def pad(message : Bytes) : Bytes
    orig_size_in_bits = message.size.to_u64 * 8
    result = Bytes.new(0)
    
    result += Bytes[0x80]
    
    while ((message.size + result.size).to_u64 * 8) % 512 != 448
      result += Bytes[0x00]
    end
    
    8.times do |i|
      result += Bytes[((orig_size_in_bits >> (8 * i)) & 0xFF).to_u8]
    end
    
    message + result
  end

  def digest(data : Bytes) : Bytes
    padded = pad(data)
    
    a0 = H0
    b0 = H1
    c0 = H2
    d0 = H3
    
    (0...padded.size).step(64) do |i|
      m = Array(UInt32).new(16, 0_u32)
      16.times do |j|
        word = 0_u32
        4.times do |k|
          byte = padded[i + j*4 + k].to_u32
          word |= byte << (8 * k)
        end
        m[j] = word
      end
      
      a = a0
      b = b0
      c = c0
      d = d0
      
      64.times do |j|
        f = 0_u32
        g = 0
        if j < 16
          f = (b & c) | ((~b) & d)
          g = j
        elsif j < 32
          f = (d & b) | ((~d) & c)
          g = (5*j + 1) % 16
        elsif j < 48
          f = b ^ c ^ d
          g = (3*j + 5) % 16
        else
          f = c ^ (b | (~d))
          g = (7*j) % 16
        end
        
        temp = a &+ f &+ K[j] &+ m[g]
        a = d
        d = c
        c = b
        b = b &+ rotate_left(temp, S[j])
      end
      
      a0 = a0 &+ a
      b0 = b0 &+ b
      c0 = c0 &+ c
      d0 = d0 &+ d
    end
    
    result = Bytes.new(16)
    4.times do |i|
      result[i] = ((a0 >> (8 * i)) & 0xFF).to_u8
      result[i + 4] = ((b0 >> (8 * i)) & 0xFF).to_u8
      result[i + 8] = ((c0 >> (8 * i)) & 0xFF).to_u8
      result[i + 12] = ((d0 >> (8 * i)) & 0xFF).to_u8
    end
    
    result
  end

  def hexdigest(data : Bytes) : String
    Crypto::Utils.bytes_to_hex(digest(data))
  end

  def hexdigest(data : String) : String
    hexdigest(data.to_slice)
  end
end
