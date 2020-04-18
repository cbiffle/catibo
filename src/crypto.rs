//! Implements crypto found in some of the file formats.
//!
//! This implements what I'm calling the "86 Cipher," which is the scrambling
//! function found in `ctb` files with an initial byte of 0x86. See the
//! documentation on `KeyStream86`.

use byteorder::{ByteOrder, LittleEndian};

/// A key stream for the 86 cipher.
///
/// This gets seeded with a `key` and `iv` at creation, and maintains the
/// cipher state as words are processed. It can be `clone`d to fork the cipher
/// state.
///
/// # Cipher details
///
/// The 86 cipher is a stream cipher that operates natively on 32-bit units, but
/// can be adapted to arbitrary-length data. It uses a 32-bit key and a 32-bit
/// initialization vector; the IV is typically incremented in successive
/// messages in the same data stream.
///
/// The 86 cipher operates by generating a pseudo-random *key stream* and
/// combining that with the plaintext using XOR.
///
/// The pseudo-random key stream is produced by a degenerate linear congruential
/// PRNG: in the step function `X[n+1] = (a * X[n]) + c`, `a` is fixed at 0, and
/// `c` is derived from the key. `X[0]` is derived from both the key and
/// initialization vector.
///
/// Concretely (all math modulo 2^32):
///
/// - `c = key * 0x2D83_CDAC + 0xD8A8_3423`
/// - `X[0] = (IV * 0x1E15_30CD + 0xEC3D_47CD) * c`
/// - `X[n+1] = X[n] + c`
///
/// And then to encrypt,
///
/// - `C[n] = X[n] ^ P[n]` (for `C` ciphertext and `P` plaintext, both streams
///   of 32-bit words).
///
/// ## Adapting to arbitrary-length data
///
/// When dealing in byte streams instead of collections of 32-bit words, the
/// cipher treats bytes as little-endian words. Because the cipher has zero
/// diffusion, we can pad the input with *arbitrary data* to the next 32-bit
/// boundary, and then truncate the result to the original length.
///
/// ## Weaknesses
///
/// Don't use this cipher for anything you care about. The only reason I've
/// implemented it is because a product I *own* requires me to use it to
/// interact with it.
#[derive(Clone, Debug)]
pub struct KeyStream86 {
    state: u32,
    step: u32,
}

impl KeyStream86 {
    /// Creates a key stream for a given key and initialization vector.
    pub fn for_key_and_iv(key: u32, iv: u32) -> Self {
        let step = key.wrapping_mul(0x2D83_CDAC).wrapping_add(0xD8A8_3423);
        let state = iv
            .wrapping_mul(0x1E15_30CD)
            .wrapping_add(0xEC3D_47CD)
            .wrapping_mul(step);
        Self { step, state }
    }

    /// Produces the next 32-bit word in the keystream. XOR this with data to
    /// encrypt or decrypt.
    pub fn next_word(&mut self) -> u32 {
        let result = self.state;
        self.state = self.state.wrapping_add(self.step);
        result
    }
}

/// Encrypts or decrypts `data` using the 86 cipher with `key` and `iv`.
pub fn crypt86_u32s(key: u32, iv: u32, data: &mut [u32]) {
    let mut ks = KeyStream86::for_key_and_iv(key, iv);
    for word in data {
        *word ^= ks.next_word();
    }
}

/// Encrypts or decrypts `data` using the 86 cipher with `key` and `iv`.
pub fn crypt86(key: u32, iv: u32, mut data: &mut [u8]) {
    let mut ks = KeyStream86::for_key_and_iv(key, iv);

    while data.len() >= 4 {
        let (four, rest) = data.split_at_mut(4);
        let word = LittleEndian::read_u32(four);
        LittleEndian::write_u32(four, word ^ ks.next_word());
        data = rest;
    }

    // Handle up to 3 trailing bytes as though they are the prefix of a
    // little-endian u32.
    let last_key_word = ks.next_word();
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= (last_key_word >> (i * 8)) as u8;
    }
}
