# src/crypto/hmac.cr

module Crypto::HMAC
  extend self

  private BLOCK_SIZE = 136

  def hmac(key : Bytes, data : Bytes) : Bytes
    k = key.dup
    
    if k.size > BLOCK_SIZE
      k = SHA3.sha3_256(k)
    end

    if k.size < BLOCK_SIZE
      padded = Bytes.new(BLOCK_SIZE, 0_u8)
      k.each_with_index { |b, i| padded[i] = b }
      k = padded
    end

    ipad = Bytes.new(BLOCK_SIZE) { |i| (k[i] ^ 0x36).to_u8 }
    opad = Bytes.new(BLOCK_SIZE) { |i| (k[i] ^ 0x5C).to_u8 }

    inner = SHA3.sha3_256(ipad + data)
    SHA3.sha3_256(opad + inner)
  end
end
