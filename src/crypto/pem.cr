# src/crypto/pem.cr

require "base64"

module Crypto::PEM
  extend self
  
  include Crypto::Utils
  include Crypto::ED521
  include Crypto::X448

  # ============================================================
  # RFC 1423 KEY DERIVATION (MD5-based)
  # ============================================================

  private def rfc1423_derive_key_md5(password : String, salt : Bytes, key_size : Int32) : Bytes
    iv_salt = salt[0, 8]
    
    d = Bytes.new(0)
    result = Bytes.new(0)
    
    while result.size < key_size
      md5_input = d + password.to_slice + iv_salt
      d = Crypto::MD5.digest(md5_input)
      result = result + d
    end
    
    result[0, key_size]
  end

  # ============================================================
  # CURUPIRA-192-CBC ENCRYPTION
  # ============================================================

  private def encrypt_curupira_cbc(data : Bytes, password : String) : String
    iv = Random::Secure.random_bytes(12)
    key = rfc1423_derive_key_md5(password, iv, 24)
    
    cipher = Crypto::Curupira1::Cipher.new(key)
    cbc = Crypto::Curupira1::CBC.new(cipher, iv)
    encrypted_data = cbc.encrypt(data)
    
    b64_data = Base64.strict_encode(encrypted_data)
    lines = b64_data.scan(/.{1,64}/).map(&.[0])
    
    String.build do |io|
      io << "Proc-Type: 4,ENCRYPTED\n"
      io << "DEK-Info: CURUPIRA-192-CBC,#{bytes_to_hex(iv)}\n"
      io << "\n"
      lines.each { |line| io << line << "\n" }
    end
  end

  private def decrypt_curupira_cbc(pem_content : String, password : String) : Bytes
    lines = pem_content.lines
    
    dek_info = nil
    b64_lines = [] of String
    in_headers = true
    
    lines.each do |line|
      line = line.strip
      
      if line.empty? && in_headers
        in_headers = false
        next
      end
      
      if in_headers
        if line.starts_with?("DEK-Info:")
          dek_info = line[10..-1].strip
        end
      else
        b64_lines << line unless line.starts_with?("-----")
      end
    end
    
    raise "Missing DEK-Info header" if dek_info.nil?
    
    dek_parts = dek_info.split(",", 2)
    raise "Invalid DEK-Info format: #{dek_info}" if dek_parts.size != 2
    
    cipher_name = dek_parts[0].strip
    iv_hex = dek_parts[1].strip
    
    raise "Unsupported cipher: #{cipher_name}" if cipher_name != "CURUPIRA-192-CBC"
    
    iv = hex_to_bytes(iv_hex)
    raise "Invalid IV length" if iv.size != 12
    
    b64_data = b64_lines.join
    encrypted_data = Base64.decode(b64_data)
    
    key = rfc1423_derive_key_md5(password, iv, 24)
    
    cipher = Crypto::Curupira1::Cipher.new(key)
    cbc = Crypto::Curupira1::CBC.new(cipher, iv)
    
    cbc.decrypt(encrypted_data)
  end

  # ============================================================
  # ED521 PEM FUNCTIONS
  # ============================================================

  def ed521_private_to_pem(private_key : BigInt, password : String? = nil) : String
    priv_bytes = little_int_to_bytes(private_key, 66)
    
    encoded_oid = Bytes[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
    oid_der = Bytes[0x06, 0x0a] + encoded_oid
    algorithm_id = Bytes[0x30, 0x0e] + oid_der + Bytes[0x05, 0x00]
    version = Bytes[0x02, 0x01, 0x00]
    priv_field = Bytes[0x04, 0x42] + priv_bytes
    
    content = version + algorithm_id + priv_field
    content_len = content.size
    
    pkcs8 = if content_len <= 0x7F
              Bytes[0x30, content_len.to_u8] + content
            else
              Bytes[0x30, 0x81, content_len.to_u8] + content
            end
    
    has_password = password && !password.empty?
    
    if has_password
      encrypted_content = encrypt_curupira_cbc(pkcs8, password.not_nil!)
      "-----BEGIN E-521 PRIVATE KEY-----\n#{encrypted_content}-----END E-521 PRIVATE KEY-----\n"
    else
      b64 = Base64.strict_encode(pkcs8)
      lines = b64.scan(/.{1,64}/).map(&.[0])
      
      String.build do |io|
        io << "-----BEGIN E-521 PRIVATE KEY-----\n"
        lines.each { |line| io << line << "\n" }
        io << "-----END E-521 PRIVATE KEY-----\n"
      end
    end
  end

  def ed521_public_to_pem(public_x : BigInt, public_y : BigInt) : String
    compressed = compress_point(public_x, public_y)
    
    encoded_oid = Bytes[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xdc, 0x2c, 0x02, 0x01]
    oid_der = Bytes[0x06, 0x0a] + encoded_oid
    algorithm_id = Bytes[0x30, 0x0e] + oid_der + Bytes[0x05, 0x00]
    
    bit_string_data = Bytes[0x00] + compressed
    bit_string_len = bit_string_data.size
    
    bit_string = if bit_string_len <= 0x7F
                   Bytes[0x03, bit_string_len.to_u8] + bit_string_data
                 else
                   Bytes[0x03, 0x81, bit_string_len.to_u8] + bit_string_data
                 end
    
    content = algorithm_id + bit_string
    content_len = content.size
    
    spki = if content_len <= 0x7F
             Bytes[0x30, content_len.to_u8] + content
           else
             Bytes[0x30, 0x81, content_len.to_u8] + content
           end
    
    b64 = Base64.strict_encode(spki)
    lines = b64.scan(/.{1,64}/).map(&.[0])
    
    String.build do |io|
      io << "-----BEGIN E-521 PUBLIC KEY-----\n"
      lines.each { |line| io << line << "\n" }
      io << "-----END E-521 PUBLIC KEY-----\n"
    end
  end

  def parse_ed521_private_pem(pem_content : String, password : String? = nil) : BigInt
    is_encrypted = pem_content.includes?("Proc-Type:") && pem_content.includes?("ENCRYPTED")
    
    if is_encrypted
      raise "Private key is encrypted but no password provided" if password.nil?
      decrypted_der = decrypt_curupira_cbc(pem_content, password)
      parse_pkcs8_der(decrypted_der)
    else
      lines = pem_content.lines
      b64_lines = lines.reject { |l| l.starts_with?("-----") }
      b64 = b64_lines.join
      der = Base64.decode(b64)
      parse_pkcs8_der(der)
    end
  end

  private def parse_pkcs8_der(der : Bytes) : BigInt
    idx = 0
    
    raise "Invalid PEM" if der[idx] != 0x30
    idx += 1
    
    if der[idx] & 0x80 != 0
      len_len = der[idx] & 0x7F
      idx += 1 + len_len
    else
      idx += 1
    end
    
    raise "Invalid version" if der[idx] != 0x02
    idx += 1
    raise "Invalid version length" if der[idx] != 0x01
    idx += 1
    raise "Version not 0" if der[idx] != 0x00
    idx += 1
    
    raise "Invalid AlgorithmIdentifier" if der[idx] != 0x30
    idx += 1
    
    if der[idx] & 0x80 != 0
      len_len = der[idx] & 0x7F
      idx += 1 + len_len
    else
      alg_len = der[idx]
      idx += 1 + alg_len
    end
    
    raise "Expected OCTET STRING" if der[idx] != 0x04
    idx += 1
    
    priv_len = der[idx].to_i
    idx += 1
    
    if priv_len == 0x81
      priv_len = der[idx].to_i
      idx += 1
    elsif priv_len == 0x82
      priv_len = (der[idx].to_i << 8) | der[idx+1].to_i
      idx += 2
    end
    
    key_bytes = der[idx, priv_len]
    bytes_to_little_int(key_bytes)
  end

  def parse_ed521_public_pem(pem_content : String) : Tuple(BigInt, BigInt)
    lines = pem_content.lines
    b64_lines = lines.reject { |l| l.starts_with?("-----") }
    b64 = b64_lines.join
    der = Base64.decode(b64)
    
    idx = 0
    
    raise "Invalid PEM" if der[idx] != 0x30
    idx += 1
    
    if der[idx] & 0x80 != 0
      len_len = der[idx] & 0x7F
      idx += 1 + len_len
    else
      idx += 1
    end
    
    raise "Invalid AlgorithmIdentifier" if der[idx] != 0x30
    idx += 1
    
    if der[idx] & 0x80 != 0
      len_len = der[idx] & 0x7F
      idx += 1 + len_len
    else
      alg_len = der[idx]
      idx += 1 + alg_len
    end
    
    raise "Expected BIT STRING" if der[idx] != 0x03
    idx += 1
    
    if der[idx] & 0x80 != 0
      len_len = der[idx] & 0x7F
      idx += 1 + len_len
    else
      idx += 1
    end
    
    unused = der[idx]
    idx += 1
    
    key_bytes = der[idx, 66]
    
    x, y = decompress_point(key_bytes)
    raise "Invalid public key" if x.nil? || y.nil?
    
    {x, y}
  end

  # ============================================================
  # X448 PEM FUNCTIONS
  # ============================================================

  def x448_private_to_pem(private_key : Bytes, password : String? = nil) : String
    if private_key.size != 56
      raise ArgumentError.new("X448 private key must be 56 bytes")
    end
    
    x448_oid = Bytes[0x06, 0x03, 0x2b, 0x65, 0x6f]
    
    inner = Bytes[0x04, 0x38] + private_key
    private_key_der = Bytes[0x04, inner.size.to_u8] + inner
    
    alg_id = Bytes[0x30, x448_oid.size.to_u8] + x448_oid
    version = Bytes[0x02, 0x01, 0x00]
    
    total_len = version.size + alg_id.size + private_key_der.size
    pkcs8 = Bytes[0x30, total_len.to_u8] + version + alg_id + private_key_der
    
    has_password = password && !password.empty?
    
    if has_password
      encrypted_content = encrypt_curupira_cbc(pkcs8, password.not_nil!)
      "-----BEGIN X448 PRIVATE KEY-----\n#{encrypted_content}-----END X448 PRIVATE KEY-----\n"
    else
      b64 = Base64.strict_encode(pkcs8)
      lines = b64.scan(/.{1,64}/).map(&.[0])
      
      String.build do |io|
        io << "-----BEGIN X448 PRIVATE KEY-----\n"
        lines.each { |line| io << line << "\n" }
        io << "-----END X448 PRIVATE KEY-----\n"
      end
    end
  end

  def x448_public_to_pem(public_key : Bytes) : String
    if public_key.size != 56
      raise ArgumentError.new("X448 public key must be 56 bytes")
    end
    
    x448_oid = Bytes[0x06, 0x03, 0x2b, 0x65, 0x6f]
    alg_id = Bytes[0x30, x448_oid.size.to_u8] + x448_oid
    
    bit_string = Bytes[0x03, (public_key.size + 1).to_u8, 0x00] + public_key
    spki = Bytes[0x30, (alg_id.size + bit_string.size).to_u8] + alg_id + bit_string
    
    b64 = Base64.strict_encode(spki)
    lines = b64.scan(/.{1,64}/).map(&.[0])
    
    String.build do |io|
      io << "-----BEGIN X448 PUBLIC KEY-----\n"
      lines.each { |line| io << line << "\n" }
      io << "-----END X448 PUBLIC KEY-----\n"
    end
  end

  def parse_x448_private_pem(pem_content : String, password : String? = nil) : Bytes
    is_encrypted = pem_content.includes?("Proc-Type:") && pem_content.includes?("ENCRYPTED")
    
    if is_encrypted
      raise "Private key is encrypted but no password provided" if password.nil?
      decrypted = decrypt_curupira_cbc(pem_content, password)
      
      # Extrair os últimos 56 bytes (a chave X448)
      if decrypted.size >= 56
        decrypted[decrypted.size - 56, 56]
      else
        raise ArgumentError.new("Invalid private key data: expected at least 56 bytes, got #{decrypted.size}")
      end
    else
      lines = pem_content.lines
      b64_lines = lines.reject { |l| l.starts_with?("-----") }
      b64 = b64_lines.join
      der = Base64.decode(b64)
      
      if der.size == 56
        der
      elsif der.size > 56
        der[der.size - 56, 56]
      else
        raise ArgumentError.new("Invalid X448 private key data: expected 56 bytes, got #{der.size}")
      end
    end
  end

  def parse_x448_public_pem(pem_content : String) : Bytes
    lines = pem_content.lines
    b64_lines = lines.reject { |l| l.starts_with?("-----") }
    b64 = b64_lines.join
    der = Base64.decode(b64)
    
    if der.size == 56
      der
    elsif der.size > 56
      der[der.size - 56, 56]
    else
      raise ArgumentError.new("Invalid X448 public key data: expected at least 56 bytes, got #{der.size}")
    end
  end
end
