# src/crypto/hkdf.cr

module Crypto::HKDF
  extend self

  private HASH_LEN = 32

  def hkdf(ikm : Bytes, length : Int32, salt : Bytes? = nil, info : Bytes = Bytes.empty) : Bytes
    salt = salt || Bytes.new(HASH_LEN, 0_u8)

    prk = HMAC.hmac(salt, ikm)

    n = (length + HASH_LEN - 1) // HASH_LEN
    raise ArgumentError.new("HKDF: length too large") if n > 255

    t = Bytes.empty
    okm = Bytes.new(0)

    1.upto(n) do |i|
      counter = Bytes[ i.to_u8 ]
      t = HMAC.hmac(prk, t + info + counter)
      okm += t
    end

    okm[0, length]
  end
end
