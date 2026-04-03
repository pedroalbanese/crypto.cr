# src/crypto.cr - Ponto de entrada principal

require "big"
require "random/secure"
require "base64"

# Require todos os submódulos na ordem correta
require "./crypto/utils"
require "./crypto/constants"
require "./crypto/sha3"
require "./crypto/hmac"
require "./crypto/hkdf"
require "./crypto/md5"
require "./crypto/ed521"
require "./crypto/x448"
require "./crypto/curupira1"
require "./crypto/anubis"
require "./crypto/pem"

module Crypto
  VERSION = "1.0.0"

  # Funções utilitárias de alto nível
  def self.hex_to_bytes(hex : String) : Bytes
    Utils.hex_to_bytes(hex)
  end

  def self.bytes_to_hex(bytes : Bytes) : String
    Utils.bytes_to_hex(bytes)
  end

  def self.constant_time_compare(a : Bytes, b : Bytes) : Bool
    Utils.constant_time_compare(a, b)
  end

  def self.xor_bytes(a : Bytes, b : Bytes) : Bytes
    Utils.xor_bytes(a, b)
  end

  def self.hash(data : Bytes) : Bytes
    SHA3.sha3_256(data)
  end

  def self.hash(data : String) : String
    bytes_to_hex(SHA3.sha3_256(data.to_slice))
  end
end
