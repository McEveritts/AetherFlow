//! Shared streaming RFC 1321 MD5 digest helper for legacy protocol compatibility
//! (RFC 2617 HTTP Digest HA1 and user-requested file checksum verification).
//! Not used for password hashing or cryptographic signatures.

#[derive(Debug, Clone)]
pub struct Md5Hasher {
    state: [u32; 4],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Default for Md5Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Md5Hasher {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    pub fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
        let mut m = [0u32; 16];
        for (idx, word) in m.iter_mut().enumerate() {
            let offset = idx * 4;
            *word = u32::from_le_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }

        let [mut a, mut b, mut c, mut d] = *state;
        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | (!b & d), i),
                16..=31 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let temp = f
                .wrapping_add(a)
                .wrapping_add(Self::K[i])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(temp.rotate_left(Self::S[i]));
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }

    pub fn update(&mut self, input: &[u8]) {
        if input.is_empty() {
            return;
        }
        self.total_len = self.total_len.wrapping_add(input.len() as u64);
        let mut offset = 0usize;

        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            if input.len() < need {
                self.buf[self.buf_len..self.buf_len + input.len()].copy_from_slice(input);
                self.buf_len += input.len();
                return;
            }
            self.buf[self.buf_len..64].copy_from_slice(&input[..need]);
            Self::compress(&mut self.state, &self.buf);
            self.buf_len = 0;
            offset = need;
        }

        while offset + 64 <= input.len() {
            let mut block = [0u8; 64];
            block.copy_from_slice(&input[offset..offset + 64]);
            Self::compress(&mut self.state, &block);
            offset += 64;
        }

        let rem = input.len() - offset;
        if rem > 0 {
            self.buf[..rem].copy_from_slice(&input[offset..]);
            self.buf_len = rem;
        }
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        let pad_len = if self.buf_len <= 56 {
            56 - self.buf_len
        } else {
            64 - self.buf_len + 56
        };
        if pad_len > 0 {
            let zeros = [0u8; 64];
            self.update(&zeros[..pad_len]);
        }
        self.update(&bit_len.to_le_bytes());

        let mut out = [0u8; 16];
        for (idx, word) in self.state.iter().enumerate() {
            out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

pub fn md5_digest(input: &[u8]) -> [u8; 16] {
    let mut hasher = Md5Hasher::new();
    hasher.update(input);
    hasher.finalize()
}
