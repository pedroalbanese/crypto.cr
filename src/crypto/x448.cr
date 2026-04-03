# src/crypto/x448.cr

require "random/secure"

module Crypto::X448
  extend self

  include Crypto::Constants
  include Crypto::Utils

  private def modp_add(a : BigInt, b : BigInt) : BigInt
    (a + b) % X448_P
  end

  private def modp_sub(a : BigInt, b : BigInt) : BigInt
    (a - b) % X448_P
  end

  private def modp_mul(a : BigInt, b : BigInt) : BigInt
    (a * b) % X448_P
  end

  private def modp_sqr(a : BigInt) : BigInt
    (a * a) % X448_P
  end

  private def modp_inv(a : BigInt) : BigInt
    exp = X448_P - 2
    result = BigInt.new(1)
    base = a % X448_P
    
    while exp > 0
      if exp.odd?
        result = (result * base) % X448_P
      end
      base = (base * base) % X448_P
      exp >>= 1
    end
    
    result
  end

  private def clamp_scalar(scalar : Bytes) : Bytes
    raise ArgumentError.new("Scalar must be 56 bytes") if scalar.size != 56
    
    clamped = scalar.dup
    clamped[0] &= 0xFC_u8
    clamped[55] |= 0x80_u8
    clamped
  end

  def scalar_mult(scalar : Bytes, point : Bytes) : Bytes
    raise ArgumentError.new("Inputs must be 56 bytes") if scalar.size != 56 || point.size != 56
    
    k = clamp_scalar(scalar)
    
    k_int = BigInt.new(0)
    56.times do |i|
      k_int |= BigInt.new(k[i]) << (i * 8)
    end
    
    u_int = BigInt.new(0)
    56.times do |i|
      u_int |= BigInt.new(point[i]) << (i * 8)
    end
    
    x1 = u_int % X448_P
    x2 = BigInt.new(1)
    z2 = BigInt.new(0)
    x3 = u_int % X448_P
    z3 = BigInt.new(1)
    swap = 0
    
    448.times do |i|
      t = 447 - i
      k_t = ((k_int >> t) & 1).to_i
      swap ^= k_t
      
      if swap == 1
        x2, x3 = x3, x2
        z2, z3 = z3, z2
      end
      swap = k_t
      
      a = modp_add(x2, z2)
      aa = modp_sqr(a)
      b = modp_sub(x2, z2)
      bb = modp_sqr(b)
      e = modp_sub(aa, bb)
      c = modp_add(x3, z3)
      d = modp_sub(x3, z3)
      da = modp_mul(d, a)
      cb = modp_mul(c, b)
      
      x3 = modp_sqr(modp_add(da, cb))
      z3 = modp_mul(modp_sqr(modp_sub(da, cb)), x1)
      x2 = modp_mul(aa, bb)
      z2 = modp_mul(modp_add(modp_mul(e, X448_A24), aa), e)
    end
    
    if swap == 1
      x2, x3 = x3, x2
      z2, z3 = z3, z2
    end
    
    raise ArgumentError.new("x448 bad input point") if z2 == 0
    
    result = modp_mul(x2, modp_inv(z2))
    
    bytes = Bytes.new(56, 0)
    56.times do |i|
      bytes[i] = ((result >> (i * 8)) & 0xFF).to_u8
    end
    
    bytes
  end

  def base_point_mult(scalar : Bytes) : Bytes
    scalar_mult(scalar, X448_BASE_POINT)
  end

  def generate_private_key : Bytes
    private_bytes = Random::Secure.random_bytes(56)
    clamp_scalar(private_bytes)
  end

  def get_public_key(private_key : Bytes) : Bytes
    base_point_mult(private_key)
  end

  def shared_secret(private_key : Bytes, peer_public_key : Bytes) : Bytes
    scalar_mult(private_key, peer_public_key)
  end
end
