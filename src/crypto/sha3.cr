# src/crypto/sha3.cr

module Crypto
  module SHA3
    extend self

    private RATE = 136
    private OUTPUT_SIZE = 32

    private RC = [
      0x0000000000000001_u64, 0x0000000000008082_u64,
      0x800000000000808A_u64, 0x8000000080008000_u64,
      0x000000000000808B_u64, 0x0000000080000001_u64,
      0x8000000080008081_u64, 0x8000000000008009_u64,
      0x000000000000008A_u64, 0x0000000000000088_u64,
      0x0000000080008009_u64, 0x000000008000000A_u64,
      0x000000008000808B_u64, 0x800000000000008B_u64,
      0x8000000000008089_u64, 0x8000000000008003_u64,
      0x8000000000008002_u64, 0x8000000000000080_u64,
      0x000000000000800A_u64, 0x800000008000000A_u64,
      0x8000000080008081_u64, 0x8000000000008080_u64,
      0x0000000080000001_u64, 0x8000000080008008_u64,
    ]

    private ROT = [
      [  0, 36,  3, 41, 18 ],
      [  1, 44, 10, 45,  2 ],
      [ 62,  6, 43, 15, 61 ],
      [ 28, 55, 25, 21, 56 ],
      [ 27, 20, 39,  8, 14 ],
    ]

    private def rotl(x : UInt64, n : Int32) : UInt64
      ((x << n) | (x >> (64 - n)))
    end

    private def keccak_f(state : Array(UInt64))
      24.times do |round|
        c = Array(UInt64).new(5) { |i|
          state[i] ^ state[i+5] ^ state[i+10] ^ state[i+15] ^ state[i+20]
        }
        d = Array(UInt64).new(5) { |i|
          c[(i+4)%5] ^ rotl(c[(i+1)%5], 1)
        }
        5.times do |i|
          5.times do |j|
            state[i + 5*j] ^= d[i]
          end
        end

        b = Array(UInt64).new(25, 0_u64)
        5.times do |x|
          5.times do |y|
            b[y + 5*((2*x + 3*y) % 5)] = rotl(state[x + 5*y], ROT[x][y])
          end
        end

        5.times do |x|
          5.times do |y|
            state[x + 5*y] = b[x + 5*y] ^ ((~b[(x+1)%5 + 5*y]) & b[(x+2)%5 + 5*y])
          end
        end

        state[0] ^= RC[round]
      end
    end

    def sha3_256(data : Bytes) : Bytes
      state = Array(UInt64).new(25, 0_u64)

      offset = 0
      data_size = data.size
      
      while offset + RATE <= data_size
        block = data[offset, RATE]
        RATE.times do |i|
          state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
        end
        keccak_f(state)
        offset += RATE
      end

      block = Bytes.new(RATE, 0_u8)
      remaining = data_size - offset
      remaining.times { |i| block[i] = data[offset + i] }
      
      block[remaining] ^= 0x06
      block[RATE - 1] ^= 0x80

      RATE.times do |i|
        state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
      end
      keccak_f(state)

      output = Bytes.new(OUTPUT_SIZE)
      OUTPUT_SIZE.times do |i|
        lane = i // 8
        shift = 8 * (i % 8)
        output[i] = ((state[lane] >> shift) & 0xFF).to_u8
      end

      output
    end

    def shake256(data : Bytes, output_len : Int32) : Bytes
      state = Array(UInt64).new(25, 0_u64)

      offset = 0
      data_size = data.size
      
      while offset + RATE <= data_size
        block = data[offset, RATE]
        RATE.times do |i|
          state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
        end
        keccak_f(state)
        offset += RATE
      end

      block = Bytes.new(RATE, 0_u8)
      remaining = data_size - offset
      remaining.times { |i| block[i] = data[offset + i] }
      block[remaining] ^= 0x1F
      block[RATE - 1] ^= 0x80

      RATE.times do |i|
        state[i // 8] ^= block[i].to_u64 << (8 * (i % 8))
      end
      keccak_f(state)

      output = Bytes.new(output_len, 0_u8)
      extracted = 0
      
      while extracted < output_len
        i = 0
        while i < RATE && extracted < output_len
          lane = i // 8
          shift = 8 * (i % 8)
          output[extracted] = ((state[lane] >> shift) & 0xFF).to_u8
          extracted += 1
          i += 1
        end
        
        if extracted < output_len
          keccak_f(state)
        end
      end

      output
    end
  end
end
