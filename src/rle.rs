//! Run-Length Encoding algorithms.
//!
//! This module implements the run-length encoding compression methods that
//! appear in supported file types. These particular algorithms appear to be
//! unique to the file formats, and so I have had to make up names for them.
//!
//! The names are based on the number of bits in each sample of the compressed
//! data: `RLE1`, `RLE7`, and `RLE15`. The printer manufacturer screwed this
//! scheme up a bit by introducing a *second* 7-bit RLE scheme, which I'm
//! calling `RLE7a`.
//!
//! # `RLE1`
//!
//! `RLE1` encodes single-bit samples (i.e. a bilevel or monochrome image) into
//! runs of up to 127 pixels. Its maximum (best-case) compression ratio is
//! 0.063x, and its worst-case inflation is 800x.
//!
//! This scheme is used by older CBDDLP files.
//!
//! The encoding is simple and operates in terms of single bytes. In each byte,
//! the 1-bit sample is in the MSB, while the 7-bit run length is in the low 7
//! bits. Thus, the byte `0x84` encodes 4 pixels containing 1s.
//!
//! # `RLE7`
//!
//! `RLE7` encodes 7-bit samples (i.e. a grayscale image) into runs of up to
//! 256ki pixels using a variable-length encoding scheme that vaguely resembles
//! UTF-8 (but is not UTF-8). Its maximum (best-case) compression ratio is
//! 2.13e-8 (i.e. very small), and its worst-case inflation is only 1.14x.
//!
//! This scheme is used by current-generation CTB files (as of spring 2020).
//!
//! The encoding works as follows:
//!
//! - 7-bit sample is stored in the 7 LSBs of the first byte.
//! - MSB clear means a run of 1 with no further encoding.
//! - MSB set means an encoded run length follows.
//! - The length (in bytes) of the encoded run length is indicated by the MSBs
//!   of the following byte.
//!   - `0b0xxx_xxxx` encodes a run of 0-127 bytes in the 7 LSBs.
//!   - `0b10xx_xxxx` encodes a 14-bit run length using the 6 LSBs and the
//!     following byte.
//!   - `0b110x_xxxx` encodes a 21-bit run length using the 5 LSBs and the
//!     following *two* bytes.
//!   - `0b1110_xxxx` encodes a 28-bit run length using the 4 LSBs and the
//!     following *three* bytes.
//!
//! When an encoded run spans multiple bytes, they appear in *big-endian order*
//! -- that is, the most significant bits of the encoded run appear in the
//! *first* byte. This is the only place in the entire file format that uses
//! big-endian.
//!
//! # `RLE7a`
//!
//! `RLE7a` encodes 7-bit samples into repeated sections of up to 127 pixels
//! using an unusual encoding scheme based on repeating previously generated
//! pixels. Its maximum (best-case) compression ratio is 0.009x, though it
//! doesn't approach this in practice, and its worst-case inflation is only
//! 1.14x.
//!
//! This scheme is used by recent file format variations including `phz`.
//!
//! The encoding works as follows:
//!
//! - A byte with the MSB set encodes a pixel in its low 7 bits.
//! - A byte with the MSB clear encodes a repetition count in its low 7 bits.
//!
//! Repetitions simply repeat the last literal pixel that was encoded.
//! Repetitions can, themselves, be repeated: `0x80 0x7f 0x7f` encodes 254
//! zero-valued pixels.
//!
//! Note that RLE7a is the only scheme described here that is *stateful* -- it's
//! not enough to simply decode bytes, one must also remember the last pixel
//! encoded. This causes its API to be pretty different.
//!
//! # `RLE15`
//!
//! `RLE15` encodes 15-bit RGB555 encoded samples into runs of up to 4096
//! pixels. Its maximum (best-case) compression ratio is 0.0005x, and its
//! worst-case inflation is just 1.07x.
//!
//! This scheme is used in all file format variations to encode RGB preview
//! images.
//!
//! The encoding works as follows:
//!
//! - Pixels are packed like RGB565 -- that is, `0bRRRRR_GGGGGG_BBBBB` -- into
//!   little-endian `u16s`, but with the least significant `G` bit not storing
//!   color information.
//! - Instead, the bit that would be G's LSB (bit 5) indicates whether a run
//!   follows (set) or if this `u16` encodes a single pixel (clear).
//! - If a run follows, it has the form `0b0011_xxxx_xxxx_xxxx` -- that is, a
//!   12-bit run encoded in the 12 LSBs of a little-endian `u16`, with the four
//!   MSBs set to `0x3`/`0b0011`

use std::cmp::Ordering;

/// Decodes a single byte of the RLE1 scheme into a run of 8-bit gray pixels.
///
/// RLE1 is a bilevel scheme, so "on" pixels are translated to level `0xFF`, and
/// "off" pixels to 0.
pub fn decode_rle1(byte: u8) -> Run {
    // Level is given by MSB.
    let level = if byte < 0x80 { 0x00 } else { 0xFF };
    // Length is given by bits 6:0.
    let len = (byte & 0x7F) as usize;
    (level, len)
}

/// Adapts an iterator over bytes to an iterator over decoded RLE1 runs.
///
/// This is an iterator counterpart to the `decode_rle1` function, which proves
/// to be useful when decoding antialiased images.
pub struct Rle1Iter<I>(I);

impl<I> From<I> for Rle1Iter<I> {
    fn from(inner: I) -> Rle1Iter<I> {
        Rle1Iter(inner)
    }
}

impl<I> Iterator for Rle1Iter<I>
where
    I: Iterator<Item = u8>,
{
    type Item = Run;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(decode_rle1)
    }
}

/// Adapts an infallible iterator over runs to an iterator over pixels, by
/// expanding the runs.
///
/// This is currently only useful for RLE1, since the other schemes can fail.
pub struct RunIter<I> {
    inner: I,
    state: Option<Run>,
}

impl<I> RunIter<I> {
    /// Gets the number of pixels remaining in the current run.
    pub fn remaining_run(&self) -> usize {
        self.state.map(|run| run.1).unwrap_or(0)
    }
}

impl<I> From<I> for RunIter<I>
where
    I: Iterator<Item = Run>,
{
    fn from(inner: I) -> Self {
        RunIter { inner, state: None }
    }
}

impl<I> Iterator for RunIter<I>
where
    I: Iterator<Item = Run>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.state.is_none() {
            // Attempt to refill.
            self.state = self.inner.next();
        }

        match self.state.take() {
            // If we're still empty, the refill failed.
            None => None,

            Some((level, len)) => {
                debug_assert!(len != 0);

                if len > 1 {
                    self.state = Some((level, len - 1));
                }

                Some(level)
            }
        }
    }
}

/// Collects a run of matching pixels from `bytes` and encodes them into a run
/// in the RLE1 scheme.
///
/// RLE1 runs can only be up to 127 bytes in length, so if there are more
/// matching pixels than that at the start of `bytes`, only a prefix gets taken.
///
/// RLE1 is a bilevel scheme, while `bytes` provides 8-bit intensity levels. To
/// translate, any 8-bit level at `threshold` or above is treated as on, and any
/// level below is treated as off.
///
/// If `bytes` is exhausted, returns `None`, otherwise always succeeds.
pub fn encode_rle1<I>(
    threshold: u8,
    bytes: &mut std::iter::Peekable<I>,
) -> Option<u8>
where
    I: Iterator<Item = u8>,
{
    let first = bytes.next()? >= threshold;
    let mut run_length = 1;
    while run_length < 0x7f {
        if let Some(&next) = bytes.peek() {
            if (next >= threshold) == first {
                // The run can continue. Consume that byte.
                bytes.next();
                run_length += 1;
            } else {
                // The run ends here.
                break;
            }
        } else {
            // The buffer has ended; truncate the run now.
            break;
        }
    }
    Some(run_length as u8 | if first { 0x80 } else { 0x00 })
}

/// Describes an error during RLE processing.
#[derive(Copy, Clone, Debug)]
pub enum RleError {
    /// A run was encoded using multiple bytes, but the input ended before it
    /// completed.
    Truncated,
    /// A run's encoding was invalid for this scheme.
    BadRunEncoding,
}

impl core::fmt::Display for RleError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            RleError::Truncated => f.write_str("truncated"),
            RleError::BadRunEncoding => f.write_str("bad encoding"),
        }
    }
}

impl std::error::Error for RleError {}

/// Common type for describing runs of 8-bit samples.
pub type Run = (u8, usize);

/// Decodes a run of pixels in the RLE7 scheme.
///
/// Runs can be encoded as anywhere between 1 and 5 bytes. This function will
/// draw bytes from the `bytes` iterator as required.
///
/// If the iterator is empty, returns `Ok(None)`.
///
/// If the iterator peters out before the run encoding completes, returns
/// `Err(Truncated)`.
///
/// There are illegal encodings in this scheme. If one is encountered, returns
/// `Err(BadRunEncoding)`.
///
/// Otherwise, returns `Ok(run)`.
pub fn decode_rle7(
    mut bytes: impl Iterator<Item = u8>,
) -> Result<Option<Run>, RleError> {
    let head = match bytes.next() {
        // Distinguish end-of-stream from truncation.
        None => return Ok(None),
        Some(x) => x,
    };

    // head[6:0] is a 7-bit intensity level. Map this to the 8-bit space.
    // TODO: I remember there being a cheaper algorithm for this that doesn't
    // involve a divide...
    let level = (usize::from(head & 0x7E) * 255 / 0x7E) as u8;

    fn next_byte_as_usize(
        bytes: &mut impl Iterator<Item = u8>,
    ) -> Result<usize, RleError> {
        Ok(usize::from(bytes.next().ok_or(RleError::Truncated)?))
    }

    if head < 0x80 {
        // MSB clear encodes a single pixel. Map it into the 0..256 space.
        Ok(Some((level, 1)))
    } else {
        // MSB set encodes a run. More bytes are required. We don't know how
        // many yet.
        let run_start = bytes.next().ok_or(RleError::Truncated)?;
        let len = if run_start < 0x80 {
            // Initial MSB clear: 7-bit run length.
            usize::from(run_start)
        } else if run_start < 0xC0 {
            // bits 7:6 == 0b10: 14-bit run length
            let x = usize::from(run_start & 0x3f);
            x << 8 | next_byte_as_usize(&mut bytes)?
        } else if run_start < 0xE0 {
            // bits 7:5 == 0b110: 21-bit run length
            let x = usize::from(run_start & 0x1f);
            let x = x << 8 | next_byte_as_usize(&mut bytes)?;
            x << 8 | next_byte_as_usize(&mut bytes)?
        } else if run_start < 0xF0 {
            // bits 7:4 == 0b1110: 28-bit run length
            let x = usize::from(run_start & 0xf);
            let x = x << 8 | next_byte_as_usize(&mut bytes)?;
            let x = x << 8 | next_byte_as_usize(&mut bytes)?;
            x << 8 | next_byte_as_usize(&mut bytes)?
        } else {
            // bits 7:4 == 0b1111 doesn't appear to be a thing.
            return Err(RleError::BadRunEncoding);
        };
        Ok(Some((level, len)))
    }
}

/// Encodes a run of identical-ish pixels into the RLE7 scheme.
///
/// RLE7 is a 7-bit scheme, so the LSB of pixels is ignored.
///
/// Any encoded pixels are consumed from `bytes`. If the run happens to cross
/// the maximum length for RLE7, it will be split, though this is pretty
/// unlikely.
///
/// Returns `None` if `bytes` is exhausted, otherwise always succeeds.
pub fn encode_rle7<I>(bytes: &mut std::iter::Peekable<I>) -> Option<Run7>
where
    I: Iterator<Item = u8>,
{
    let first = bytes.next()? >> 1;
    let mut run_length = 1usize;
    while run_length < (1 << 28) - 1 {
        if let Some(&next) = bytes.peek() {
            if (next >> 1) == first {
                // The run can continue. Consume that byte.
                bytes.next();
                run_length += 1;
            } else {
                // The run ends here.
                break;
            }
        } else {
            // The buffer has ended; truncate the run now.
            break;
        }
    }
    match run_length {
        1 => Some(Run7::R1(first)),
        2..=0x7f => Some(Run7::R2([first | 0x80, run_length as u8])),
        0x80..=0x3fff => Some(Run7::R3([
            first | 0x80,
            (run_length >> 8) as u8 | 0x80,
            run_length as u8,
        ])),
        0x4000..=0x1f_ffff => Some(Run7::R4([
            first | 0x80,
            (run_length >> 16) as u8 | 0xc0,
            (run_length >> 8) as u8,
            run_length as u8,
        ])),
        0x20_0000..=0xfff_ffff => Some(Run7::R5([
            first | 0x80,
            (run_length >> 24) as u8 | 0xe0,
            (run_length >> 16) as u8,
            (run_length >> 8) as u8,
            run_length as u8,
        ])),
        _ => unreachable!("0 and out-of-range should be prevented above"),
    }
}

/// RLE7 run encoding of one to five bytes.
///
/// This type exists so that we can return a 1-5 byte slice without allocating.
#[derive(Copy, Clone, Debug)]
pub enum Run7 {
    /// One byte encoding.
    R1(u8),
    /// Two byte encoding.
    R2([u8; 2]),
    /// Three byte encoding.
    R3([u8; 3]),
    /// Four byte encoding.
    R4([u8; 4]),
    /// Five byte encoding.
    R5([u8; 5]),
}

impl Run7 {
    /// Views this run as a slice for I/O purposes.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Run7::R1(x) => std::slice::from_ref(x),
            Run7::R2(bs) => &bs[..],
            Run7::R3(bs) => &bs[..],
            Run7::R4(bs) => &bs[..],
            Run7::R5(bs) => &bs[..],
        }
    }
}

/// Returns an iterator that yields runs of pixels in the RLE7a scheme until
/// `bytes` is exhausted.
pub fn decode_rle7a(
    mut bytes: impl Iterator<Item = u8>,
) -> impl Iterator<Item = Result<Run, RleError>> {
    let mut last = None;
    std::iter::from_fn(move || {
        let b = bytes.next()?;
        if b & 0x80 != 0 {
            // new pixel value
            last = Some(b << 1);
            Some(Ok((b << 1, 1)))
        } else {
            // run
            match last {
                None => Some(Err(RleError::BadRunEncoding)),
                Some(v) => Some(Ok((v, usize::from(b)))),
            }
        }
    })
}

/// Returns an iterator that yields the RLE7a encoded version of `pixels` until
/// `pixels` is exhausted.
pub fn encode_rle7a(
    pixels: impl Iterator<Item = u8>,
) -> impl Iterator<Item = u8> {
    let mut pixels = pixels.peekable();

    let mut current = None;
    std::iter::from_fn(move || {
        // Collect pixels matching `current` until we exhaust our maximum run
        // length, or the pixels change, whichever comes first.
        let mut run_length = 0;
        while run_length < 0x7f {
            // Merely peek at the next pixel, because if it's different, we'll
            // have to put it back.
            if let Some(val) = pixels.peek() {
                // Quantize to 7bpp.
                let p = val >> 1;
                // Does it match our current run?
                if current == Some(p) {
                    // Count it, drop it, and proceed.
                    run_length += 1;
                    pixels.next();
                } else if run_length > 0 {
                    // This pixel doesn't match, but we've counted at least one
                    // pixel that did -- we need to emit it as a run and leave
                    // this pixel for later. We've already got code for emitting
                    // a run when our length is exceeded after the loop -- use
                    // it.
                    break;
                } else {
                    // This pixel doesn't match, but neither did the last one --
                    // no run is in progress. We can just emit this and start a
                    // new run.
                    current = Some(p);
                    pixels.next();
                    return Some(p | 0x80u8);
                }
            } else {
                // We've run out of input, but we may have accumulated a run.
                if run_length > 0 {
                    break;
                }
                return None;
            };
        }
        debug_assert!(run_length > 0);
        Some(run_length)
    })
}

/// Equivalent to `Run` for RGB images.
pub type RgbRun = ((u8, u8, u8), usize);

/// Decodes pixels encoded in RLE15 format.
///
/// This will pull bytes from `bytes` as needed to decode a single run.
///
/// If `bytes` is exhausted at entry to this function, returns `Ok(None)`. If it
/// becomes exhausted during the decoding of the run, returns `Err(Truncated)`.
///
/// If the most significant nibble of the final byte of an encoded run is not
/// `0x3`, returns `Err(BadRunEncoding)` to warn of data corruption.
pub fn decode_rle15(
    mut bytes: impl Iterator<Item = u8>,
) -> Result<Option<RgbRun>, RleError> {
    fn decode_565(value: u16) -> (u8, u8, u8) {
        (
            ((value >> 11) as u8 & 0x1f) * 8,
            ((value >> 5) as u8 & 0x3f) * 4,
            (value as u8 & 0x1f) * 8,
        )
    }

    let head_lsb = match bytes.next() {
        // Distinguish end-of-stream from truncation.
        None => return Ok(None),
        Some(x) => x,
    };
    let head_msb = bytes.next().ok_or(RleError::Truncated)?;
    let head = u16::from(head_msb) << 8 | u16::from(head_lsb);

    // head[15:0] is an RGB 565 encoded pixel value. The green LSB is overloaded
    // to indicate the presence or absence of a run.
    if head & 0x20 == 0 {
        return Ok(Some((decode_565(head), 1)));
    }

    // We are expecting a run count. Run counts are encoded strangely: it's a
    // 12-bit number encoded as 16 bits with the top nibble set to 3.
    let run_lsb = bytes.next().ok_or(RleError::Truncated)?;
    let run_msb = bytes.next().ok_or(RleError::Truncated)?;
    let run = u16::from(run_msb) << 8 | u16::from(run_lsb);

    if run & 0xF000 != 0x3000 {
        return Err(RleError::BadRunEncoding);
    }

    let length = usize::from(run & 0xFFF) + 1;

    Ok(Some((decode_565(head), length)))
}

/// Encodes a run of identical-ish pixels in the RLE15 scheme.
///
/// RLE15 encodes RGB555 pixels, while our input is 24-bit, so the input will
/// get quantized before compression.
///
/// Consumes pixels as needed from `pixels`, producing a `Run12` unless the
/// input is exhausted.
pub fn encode_rle15<I>(pixels: &mut std::iter::Peekable<I>) -> Option<Run12>
where
    I: Iterator<Item = (u8, u8, u8)>,
{
    fn encode_565(p: (u8, u8, u8)) -> u16 {
        u16::from(p.2 >> 3)
            | u16::from(p.1 >> 2) << 5
            | u16::from(p.0 >> 3) << 11
    }

    let first = encode_565(pixels.next()?);

    let mut run_length = 1usize;
    while run_length < 0xFFF {
        if let Some(&next) = pixels.peek() {
            if encode_565(next) == first {
                // The run can continue. Consume that pixel.
                pixels.next();
                run_length += 1;
            } else {
                // The run ends here.
                break;
            }
        } else {
            // The buffer has ended; truncate the run now.
            break;
        }
    }
    match run_length.cmp(&2) {
        Ordering::Greater => Some(Run12::Double(
            first | 0x20,
            (run_length - 1) as u16 | 0x3000,
        )),
        Ordering::Equal => Some(Run12::Double(first & !0x20, first & !0x20)),
        Ordering::Less => Some(Run12::Single(first & !0x20)),
    }
}

/// A description of the encoding of a single run in the RLE15 scheme.
pub enum Run12 {
    /// One little-endian `u16` is required.
    Single(u16),
    /// Two little-endian `u16`s are required.
    Double(u16, u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_iter() {
        let runs = [(1u8, 2usize), (2, 1), (3, 3)];
        let ri = RunIter::from(runs.iter().cloned());
        assert_eq!(ri.collect::<Vec<_>>(), &[1, 1, 2, 3, 3, 3]);

        let runs = [(1u8, 42usize), (2, 1), (3, 90)];
        let ri = RunIter::from(runs.iter().cloned());
        assert_eq!(ri.count(), 42 + 1 + 90);
    }

    #[test]
    fn encode_rle7a_basic() {
        // Construct some huge runs by manipulating iterators.
        let one_thousand_twos = std::iter::repeat(4).take(1000);
        let a_three = std::iter::once(6);
        let edge_case = std::iter::repeat(8).take(128);
        let two_fives = std::iter::repeat(10).take(2);
        let seq = one_thousand_twos
            .chain(a_three)
            .chain(edge_case)
            .chain(two_fives);

        let encoded = encode_rle7a(seq).collect::<Vec<_>>();

        assert_eq!(
            encoded,
            &[
                0x82, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x6e, 0x83,
                0x84, 0x7f, 0x85, 0x01,
            ]
        );
    }
}
