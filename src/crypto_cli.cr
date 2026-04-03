#!/usr/bin/env crystal

require "option_parser"
require "./crypto"

# ============================================================
# CLI Tool for Crypto Library
# Based on original implementation
# ============================================================

VERSION = "1.0.0"
COPYRIGHT = "ALBANESE Research Lab"

class Config
  property command : String = ""
  property subcommand : String = ""
  property priv : String? = nil
  property pub : String? = nil
  property input_file : String? = nil
  property text : String? = nil
  property output_file : String? = nil
  property sig : String? = nil
  property proof : String? = nil
  property password : String? = nil
  property new_password : String? = nil
  property name : String = "key"
  property out_dir : String = "."
  property debug : Bool = false
  property key : String? = nil
  property aad : String? = nil
  property peer_key : String? = nil
  property len : Int32? = nil
  property salt : String? = nil
  property info : String? = nil
  property recursive : Bool = false
end

def print_short_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli <command> [options]"
  puts ""
  puts "Available commands:"
  puts "  ed521                         E-521 curve for signatures and ZKP"
  puts "  x448                          X448 curve for key exchange"
  puts "  anubis                        Anubis-GCM cipher for encryption"
  puts "  hmac                          Generate HMAC-SHA3-256"
  puts "  hkdf                          Derive key with HKDF-SHA3-256"
  puts "  hash                          Generate SHA3-256 hash of file(s)"
  puts "  check                         Verify files with SHA3-256 checklist"
  puts "  change-password               Change private key password"
  puts ""
  puts "For more details, use: ./crypto_cli help <command>"
  exit
end

def print_ed521_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli ed521 <command> [options]"
  puts ""
  puts "ED521 commands:"
  puts "  keygen                        Generate ED521 key pair"
  puts "    --priv FILE                 File to save private key"
  puts "    --pub FILE                  File to save public key"
  puts "    --password PASSWORD         Encrypt private key with password"
  puts ""
  puts "  sign                          Sign message with ED521"
  puts "    --priv FILE                 Private key file"
  puts "    --file FILE                 File to sign"
  puts "    --text TEXT                 Text to sign"
  puts "    --output FILE               File to save signature"
  puts "    --sig HEX                   Signature in hex (output)"
  puts "    --password PASSWORD         Private key password"
  puts ""
  puts "  verify                        Verify ED521 signature"
  puts "    --pub FILE                  Public key file"
  puts "    --file FILE                 File to verify"
  puts "    --text TEXT                 Text to verify"
  puts "    --sig HEX                   Signature in hex (input)"
  puts ""
  puts "  prove                         Generate ZKP proof of key knowledge"
  puts "    --priv FILE                 Private key file"
  puts "    --output FILE               File to save proof"
  puts "    --proof HEX                 Proof in hex (output)"
  puts "    --password PASSWORD         Private key password"
  puts ""
  puts "  verify-proof                  Verify ZKP proof"
  puts "    --pub FILE                  Public key file"
  puts "    --proof HEX                 Proof in hex (input)"
  exit
end

def print_x448_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli x448 <command> [options]"
  puts ""
  puts "X448 commands:"
  puts "  keygen                        Generate X448 key pair"
  puts "    --priv FILE                 File to save private key"
  puts "    --pub FILE                  File to save public key"
  puts "    --password PASSWORD         Encrypt private key with password"
  puts ""
  puts "  shared                        Calculate X448 shared secret"
  puts "    --priv FILE                 Private key file"
  puts "    --peer-key FILE             Peer's public key file"
  puts "    --output FILE               File to save secret"
  puts "    --password PASSWORD         Private key password"
  exit
end

def print_anubis_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli anubis <command> [options]"
  puts ""
  puts "Anubis commands:"
  puts "  encrypt                       Encrypt with Anubis-GCM"
  puts "    --key VALUE                 Key (file or hex)"
  puts "    --file FILE                 File to encrypt"
  puts "    --text TEXT                 Text to encrypt"
  puts "    --output FILE               Output file"
  puts "    --aad TEXT                  Additional Authenticated Data"
  puts ""
  puts "  decrypt                       Decrypt with Anubis-GCM"
  puts "    --key VALUE                 Key (file or hex)"
  puts "    --file FILE                 File to decrypt"
  puts "    --output FILE               Output file"
  puts "    --aad TEXT                  Additional Authenticated Data"
  exit
end

def print_hmac_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli hmac [options]"
  puts ""
  puts "Options:"
  puts "  --key VALUE                   Key (string)"
  puts "  --file FILE                   File to authenticate"
  puts "  --text TEXT                   Text to authenticate"
  exit
end

def print_hkdf_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli hkdf [options]"
  puts ""
  puts "Options:"
  puts "  --key VALUE                   IKM (string)"
  puts "  --len N                       Output size in bytes"
  puts "  --salt VALUE                  Salt (string, optional)"
  puts "  --info TEXT                   Info (optional)"
  exit
end

def print_hash_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli hash [options]"
  puts ""
  puts "Options:"
  puts "  --file FILE                   File(s) to hash (use * for multiple)"
  puts "  --text TEXT                   Text to hash"
  puts "  --recursive                   For directories, hash recursively"
  exit
end

def print_check_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli check [options]"
  puts ""
  puts "Options:"
  puts "  --file FILE                   Checklist file"
  puts ""
  puts "Or use pipe:"
  puts "  ./crypto_cli hash --file * | ./crypto_cli check"
  exit
end

def print_change_password_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli change-password [options]"
  puts ""
  puts "Options:"
  puts "  --priv FILE                   Private key file"
  puts "  --password PASSWORD           Current password"
  puts "  --new-password PASSWORD       New password"
  exit
end

def print_long_help
  puts "Crypto Tool v#{VERSION} - #{COPYRIGHT}"
  puts "=" * 70
  puts "Usage: ./crypto_cli <command> [options]"
  puts ""
  puts "Available commands:"
  puts "  ed521                         E-521 curve for signatures and ZKP"
  puts "  x448                          X448 curve for key exchange"
  puts "  anubis                        Anubis-GCM cipher for encryption"
  puts "  hmac                          Generate HMAC-SHA3-256"
  puts "  hkdf                          Derive key with HKDF-SHA3-256"
  puts "  hash                          Generate SHA3-256 hash of file(s)"
  puts "  check                         Verify files with SHA3-256 checklist"
  puts "  change-password               Change ED521 private key password"
  puts ""
  puts "For specific help:"
  puts "  ./crypto_cli help ed521"
  puts "  ./crypto_cli help x448"
  puts "  ./crypto_cli help anubis"
  puts "  ./crypto_cli help hmac"
  puts "  ./crypto_cli help hkdf"
  puts "  ./crypto_cli help hash"
  puts "  ./crypto_cli help check"
  puts "  ./crypto_cli help change-password"
  exit
end

config = Config.new

if ARGV.size == 0
  print_short_help
end

parser = OptionParser.new

parser.on("--priv FILE", "Private key file") { |f| config.priv = f }
parser.on("--pub FILE", "Public key file") { |f| config.pub = f }
parser.on("--file FILE", "File to process") { |f| config.input_file = f }
parser.on("--text TEXT", "Text to process") { |t| config.text = t }
parser.on("--output FILE", "Output file") { |o| config.output_file = o }
parser.on("--sig HEX", "Signature in hexadecimal") { |h| config.sig = h }
parser.on("--proof HEX", "ZKP proof in hexadecimal") { |h| config.proof = h }
parser.on("--password PASSWORD", "Password") { |p| config.password = p }
parser.on("--new-password PASSWORD", "New password") { |p| config.new_password = p }
parser.on("--debug", "Debug mode") { config.debug = true }
parser.on("--key VALUE", "Key (string) for HMAC/HKDF") { |v| config.key = v }
parser.on("--aad TEXT", "Additional Authenticated Data") { |a| config.aad = a }
parser.on("--peer-key FILE", "Peer's public key file") { |p| config.peer_key = p }
parser.on("--len N", "Output size in bytes") { |n| config.len = n.to_i }
parser.on("--salt VALUE", "Salt for HKDF (string)") { |s| config.salt = s }
parser.on("--info TEXT", "Info for HKDF") { |i| config.info = i }
parser.on("--recursive", "For directories, hash recursively") { config.recursive = true }
parser.on("-h", "--help", "Show help") { 
  if config.command.empty?
    print_long_help
  else
    case config.command
    when "ed521" then print_ed521_help
    when "x448" then print_x448_help
    when "anubis" then print_anubis_help
    when "hmac" then print_hmac_help
    when "hkdf" then print_hkdf_help
    when "hash" then print_hash_help
    when "check" then print_check_help
    when "change-password" then print_change_password_help
    else print_long_help
    end
  end
  exit
}

begin
  parser.parse(ARGV)
  
  if ARGV.size >= 1
    config.command = ARGV[0]
  else
    print_short_help
  end
  
  config.subcommand = ARGV.size >= 2 ? ARGV[1] : ""
  
  if ["ed521", "x448", "anubis"].includes?(config.command) && config.subcommand.empty?
    puts "Error: #{config.command} requires a subcommand"
    puts "Use: ./crypto_cli help #{config.command} for more information"
    exit 1
  end
rescue ex
  STDERR.puts "Error: #{ex.message}"
  exit 1
end

def get_message_data(config : Config) : Bytes
  if config.text && config.input_file
    raise "Error: use --text OR --file, not both"
  elsif config.text
    config.text.not_nil!.to_slice
  elsif config.input_file
    if config.input_file == "-"
      STDIN.gets_to_end.to_slice
    else
      File.read(config.input_file.not_nil!).to_slice
    end
  else
    raise "Error: provide --text or --file"
  end
end

def ensure_dir(dir : String)
  Dir.mkdir_p(dir) unless Dir.exists?(dir)
end

def read_key_from_string(key_str : String) : Bytes
  if File.exists?(key_str)
    content = File.read(key_str).strip
    if content.size == 32 || content.size == 64 || content.size == 128
      begin
        return Crypto.hex_to_bytes(content)
      rescue
        return content.to_slice
      end
    else
      return content.to_slice
    end
  else
    begin
      return Crypto.hex_to_bytes(key_str)
    rescue
      return key_str.to_slice
    end
  end
end

def hash_file_sha3(path : String) : String
  data = File.read(path).to_slice
  Crypto.bytes_to_hex(Crypto::SHA3.sha3_256(data))
end

def hash_directory_sha3(path : String, recursive : Bool) : String
  entries = [] of String
  
  Dir.each_child(path) do |entry|
    next if entry == "." || entry == ".."
    
    full_path = File.join(path, entry)
    if File.directory?(full_path)
      if recursive
        sub_hash = hash_directory_sha3(full_path, recursive)
        entries << "#{entry}/:#{sub_hash}"
      end
    else
      entries << "#{entry}:#{hash_file_sha3(full_path)}"
    end
  end
  
  entries.sort!
  
  combined = entries.join("\n").to_slice
  Crypto.bytes_to_hex(Crypto::SHA3.sha3_256(combined))
end

def hash_path_sha3(path : String, recursive : Bool) : String
  if File.directory?(path)
    hash_directory_sha3(path, recursive)
  else
    hash_file_sha3(path)
  end
end

# ============================================================
# Command execution (versão COMPLETA)
# ============================================================

case config.command
when "ed521"
  case config.subcommand
  when "keygen"
    if config.priv.nil? || config.pub.nil?
      STDERR.puts "Error: keygen requires --priv and --pub"
      exit 1
    end
    
    ensure_dir(File.dirname(config.priv.not_nil!))
    ensure_dir(File.dirname(config.pub.not_nil!))
    
    password = config.password
    
    puts "Generating ED521 key pair..."
    
    private_key = Crypto::ED521.generate_private_key
    pub_x, pub_y = Crypto::ED521.get_public_key(private_key)
    
    if password && !password.empty?
      private_pem = Crypto::PEM.ed521_private_to_pem(private_key, password)
      puts "Private key encrypted with Curupira192-CBC"
    else
      private_pem = Crypto::PEM.ed521_private_to_pem(private_key)
    end
    
    public_pem = Crypto::PEM.ed521_public_to_pem(pub_x, pub_y)
    
    File.write(config.priv.not_nil!, private_pem)
    File.write(config.pub.not_nil!, public_pem)
    
    puts "OK: ED521 key pair generated:"
    puts "  Private: #{config.priv}" + (password ? " (encrypted)" : "")
    puts "  Public: #{config.pub}"
    
    exit 0
    
  when "sign"
    if config.priv.nil?
      STDERR.puts "Error: sign requires --priv"
      exit 1
    end
    
    begin
      msg = get_message_data(config)
      
      pem = File.read(config.priv.not_nil!)
      is_encrypted = pem.includes?("Proc-Type:") && pem.includes?("ENCRYPTED")
      
      password = config.password
      if is_encrypted && password.nil?
        STDERR.puts "Error: Private key is encrypted, provide --password"
        exit 1
      end
      
      private_key = Crypto::PEM.parse_ed521_private_pem(pem, password)
      
      signature = Crypto::ED521.sign(private_key, msg)
      
      if config.output_file
        File.write(config.output_file.not_nil!, signature)
        puts "ED521 signature saved to: #{config.output_file}"
      elsif config.sig
        File.write(config.sig.not_nil!, Crypto.bytes_to_hex(signature))
        puts "ED521 signature saved to: #{config.sig}"
      else
        puts Crypto.bytes_to_hex(signature)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  when "verify"
    if config.pub.nil?
      STDERR.puts "Error: verify requires --pub"
      exit 1
    end
    
    if config.sig.nil?
      STDERR.puts "Error: verify requires --sig"
      exit 1
    end
    
    begin
      msg = get_message_data(config)
      
      pem = File.read(config.pub.not_nil!)
      pub_x, pub_y = Crypto::PEM.parse_ed521_public_pem(pem)
      
      signature = Crypto.hex_to_bytes(config.sig.not_nil!)
      
      valid = Crypto::ED521.verify(pub_x, pub_y, msg, signature)
      
      if valid
        puts "ED521 SIGNATURE VALID"
        exit 0
      else
        puts "ED521 SIGNATURE INVALID"
        exit 1
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  when "prove"
    if config.priv.nil?
      STDERR.puts "Error: prove requires --priv"
      exit 1
    end
    
    begin
      pem = File.read(config.priv.not_nil!)
      is_encrypted = pem.includes?("Proc-Type:") && pem.includes?("ENCRYPTED")
      
      password = config.password
      if is_encrypted && password.nil?
        STDERR.puts "Error: Private key is encrypted, provide --password"
        exit 1
      end
      
      private_key = Crypto::PEM.parse_ed521_private_pem(pem, password)
      
      proof = Crypto::ED521.prove_knowledge(private_key)
      
      if config.output_file
        File.write(config.output_file.not_nil!, proof)
        puts "ED521 ZKP proof saved to: #{config.output_file}"
      elsif config.proof
        File.write(config.proof.not_nil!, Crypto.bytes_to_hex(proof))
        puts "ED521 ZKP proof saved to: #{config.proof}"
      else
        puts Crypto.bytes_to_hex(proof)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  when "verify-proof"
    if config.pub.nil?
      STDERR.puts "Error: verify-proof requires --pub"
      exit 1
    end
    
    if config.proof.nil?
      STDERR.puts "Error: verify-proof requires --proof"
      exit 1
    end
    
    begin
      pem = File.read(config.pub.not_nil!)
      pub_x, pub_y = Crypto::PEM.parse_ed521_public_pem(pem)
      
      proof = Crypto.hex_to_bytes(config.proof.not_nil!)
      
      valid = Crypto::ED521.verify_knowledge(pub_x, pub_y, proof)
      
      if valid
        puts "ED521 ZKP PROOF VALID"
        exit 0
      else
        puts "ED521 ZKP PROOF INVALID"
        exit 1
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  else
    puts "Unknown ED521 command: #{config.subcommand}"
    puts "Use: ./crypto_cli help ed521"
    exit 1
  end

when "x448"
  case config.subcommand
  when "keygen"
    if config.priv.nil? || config.pub.nil?
      STDERR.puts "Error: keygen requires --priv and --pub"
      exit 1
    end
    
    ensure_dir(File.dirname(config.priv.not_nil!))
    ensure_dir(File.dirname(config.pub.not_nil!))
    
    password = config.password
    
    puts "Generating X448 key pair..."
    
    private_key = Crypto::X448.generate_private_key
    public_key = Crypto::X448.get_public_key(private_key)
    
    if password && !password.empty?
      private_pem = Crypto::PEM.x448_private_to_pem(private_key, password)
      puts "Private key encrypted with Curupira192-CBC"
    else
      private_pem = Crypto::PEM.x448_private_to_pem(private_key)
    end
    
    public_pem = Crypto::PEM.x448_public_to_pem(public_key)
    
    File.write(config.priv.not_nil!, private_pem)
    File.write(config.pub.not_nil!, public_pem)
    
    puts "OK: X448 key pair generated:"
    puts "  Private: #{config.priv}" + (password ? " (encrypted)" : "")
    puts "  Public: #{config.pub}"
    
    exit 0
    
  when "shared"
    if config.priv.nil?
      STDERR.puts "Error: shared requires --priv"
      exit 1
    end
    
    if config.peer_key.nil?
      STDERR.puts "Error: shared requires --peer-key"
      exit 1
    end
    
    begin
      # Ler chave privada
      pem_content = File.read(config.priv.not_nil!).strip
      is_encrypted = pem_content.includes?("Proc-Type:") && pem_content.includes?("ENCRYPTED")
      
      password = config.password
      if is_encrypted && password.nil?
        STDERR.puts "Error: Private key is encrypted, provide --password"
        exit 1
      end
      
      private_key = Crypto::PEM.parse_x448_private_pem(pem_content, password)
      
      # Ler chave pública do peer
      peer_pem = File.read(config.peer_key.not_nil!).strip
      peer_key = Crypto::PEM.parse_x448_public_pem(peer_pem)
      
      # Calcular shared secret
      shared = Crypto::X448.shared_secret(private_key, peer_key)
      
      if config.output_file
        File.write(config.output_file.not_nil!, Crypto.bytes_to_hex(shared))
        puts "X448 shared secret saved to: #{config.output_file}"
      else
        puts Crypto.bytes_to_hex(shared)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  else
    puts "Unknown X448 command: #{config.subcommand}"
    puts "Use: ./crypto_cli help x448"
    exit 1
  end

when "anubis"
  case config.subcommand
  when "encrypt"
    if config.key.nil?
      STDERR.puts "Error: encrypt requires --key"
      exit 1
    end
    
    begin
      key_data = read_key_from_string(config.key.not_nil!)
      
      nonce = Random::Secure.random_bytes(12)
      
      aad = config.aad ? config.aad.not_nil!.to_slice : Bytes.new(0)
      plaintext = get_message_data(config)
      
      anubis = Crypto::Anubis::AEAD.new(key_data)
      ciphertext_with_tag = anubis.seal(nonce, plaintext, aad)
      
      output = Bytes.new(nonce.size + ciphertext_with_tag.size)
      nonce.size.times { |i| output[i] = nonce[i] }
      ciphertext_with_tag.size.times { |i| output[nonce.size + i] = ciphertext_with_tag[i] }
      
      if config.output_file
        File.write(config.output_file.not_nil!, output)
        puts "Anubis-GCM encrypted data saved to: #{config.output_file}"
      else
        STDOUT.write(output)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  when "decrypt"
    if config.key.nil?
      STDERR.puts "Error: decrypt requires --key"
      exit 1
    end
    
    begin
      key_data = read_key_from_string(config.key.not_nil!)
      
      encrypted_data = get_message_data(config)
      
      if encrypted_data.size < 28
        STDERR.puts "Error: invalid encrypted data"
        exit 1
      end
      
      nonce = encrypted_data[0, 12]
      ciphertext_with_tag = encrypted_data[12..-1]
      
      aad = config.aad ? config.aad.not_nil!.to_slice : Bytes.new(0)
      
      anubis = Crypto::Anubis::AEAD.new(key_data)
      plaintext = anubis.open(nonce, ciphertext_with_tag, aad)
      
      if plaintext.nil?
        STDERR.puts "Anubis-GCM DECRYPTION FAILED: invalid tag"
        exit 1
      end
      
      if config.output_file
        File.write(config.output_file.not_nil!, plaintext)
        puts "Anubis-GCM decrypted data saved to: #{config.output_file}"
      else
        STDOUT.write(plaintext)
      end
    rescue e
      STDERR.puts "Error: #{e.message}"
      exit 1
    end
    
  else
    puts "Unknown Anubis command: #{config.subcommand}"
    puts "Use: ./crypto_cli help anubis"
    exit 1
  end

when "hmac"
  if config.key.nil?
    STDERR.puts "Error: hmac requires --key"
    exit 1
  end
  
  if config.input_file.nil? && config.text.nil?
    STDERR.puts "Error: hmac requires --file or --text"
    exit 1
  end
  
  key_data = config.key.not_nil!.to_slice
  data = get_message_data(config)
  
  mac = Crypto::HMAC.hmac(key_data, data)
  puts Crypto.bytes_to_hex(mac)

when "hkdf"
  if config.key.nil?
    STDERR.puts "Error: hkdf requires --key"
    exit 1
  end
  
  if config.len.nil?
    STDERR.puts "Error: hkdf requires --len"
    exit 1
  end
  
  ikm = config.key.not_nil!.to_slice
  salt = config.salt ? config.salt.not_nil!.to_slice : nil
  info = config.info ? config.info.not_nil!.to_slice : Bytes.empty
  
  okm = Crypto::HKDF.hkdf(ikm, config.len.not_nil!, salt, info)
  puts Crypto.bytes_to_hex(okm)

when "hash"
  if config.input_file.nil? && config.text.nil?
    STDERR.puts "Error: hash requires --file or --text"
    exit 1
  end
  
  if config.text
    data = config.text.not_nil!.to_slice
    puts Crypto.bytes_to_hex(Crypto::SHA3.sha3_256(data))
  else
    pattern = config.input_file.not_nil!
    
    if config.recursive
      if pattern.includes?('/')
        pattern = File.join(pattern, "**", "*")
      else
        pattern = "**/#{pattern}"
      end
    end
    
    files = Dir.glob(pattern).sort
    
    if files.empty?
      STDERR.puts "Error: No files found: #{config.input_file.not_nil!}"
      exit 1
    end
    
    files.each do |file|
      if File.directory?(file)
        next
      else
        hash = hash_file_sha3(file)
        puts "#{hash} *#{file}"
      end
    end
  end

when "check"
  if config.input_file.nil? && STDIN.tty?
    STDERR.puts "Error: check requires --file or pipe input"
    exit 1
  end
  
  checklist = if config.input_file
                File.read_lines(config.input_file.not_nil!)
              else
                STDIN.each_line.to_a
              end
  
  errors = 0
  total = 0
  
  checklist.each do |line|
    line = line.strip
    next if line.empty?
    
    if line.includes?('*')
      parts = line.split('*', 2)
      expected_hash = parts[0].strip
      file_path = parts[1].strip
    else
      parts = line.split(' ', 2)
      next if parts.size != 2
      expected_hash = parts[0].strip
      file_path = parts[1].strip
    end
    
    total += 1
    
    if File.exists?(file_path)
      actual_hash = hash_file_sha3(file_path)
      if actual_hash == expected_hash
        puts "#{file_path}: OK"
      else
        puts "#{file_path}: FAILED"
        errors += 1
      end
    else
      puts "#{file_path}: File not found"
      errors += 1
    end
  end
  
  if errors == 0
    puts "All #{total} files verified successfully."
    exit 0
  else
    puts "#{errors} of #{total} files failed verification."
    exit 1
  end

when "change-password"
  STDERR.puts "Change password command - implementar"
  exit 1

when "help"
  if config.subcommand.empty?
    print_long_help
  else
    case config.subcommand
    when "ed521" then print_ed521_help
    when "x448" then print_x448_help
    when "anubis" then print_anubis_help
    when "hmac" then print_hmac_help
    when "hkdf" then print_hkdf_help
    when "hash" then print_hash_help
    when "check" then print_check_help
    when "change-password" then print_change_password_help
    else
      puts "Help not available for: #{config.subcommand}"
      print_long_help
    end
  end
  exit 0

else
  puts "Unknown command: #{config.command}"
  puts "Use ./crypto_cli help for assistance"
  exit 1
end
