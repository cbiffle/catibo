//! Support for reading file formats implemented by this library.

use std::mem::size_of;

use num_traits::FromPrimitive;
use zerocopy::{FromBytes, LayoutVerified, Unaligned};

use crate::crypto;
use crate::rle;
use crate::{
    ExtConfig, ExtConfig2, HeaderStyle, ImageHeader, LayerHeader, Magic,
    MagicHeader, OmniHeader, SplitHeader,
};

/// Borrows from an in-memory file image to indicate all known records in the
/// file. This is the zero-copy way of reading files.
///
/// Each field in this struct references some part of an in-memory file image
/// with lifetime `'a`.
pub struct Layout<'a> {
    /// Magic header.
    pub magic: &'a MagicHeader,
    /// Variations on file header.
    pub header: Headers<'a>,
    /// Machine type name.
    pub machine_type: &'a [u8],
    /// Image header for the larger preview image.
    pub large_preview_header: &'a ImageHeader,
    /// Encoded image data for the larger preview image.
    pub large_preview_data: &'a [u8],
    /// Image header for the smaller preview image.
    pub small_preview_header: &'a ImageHeader,
    /// Encoded image data for the smaller preview image.
    pub small_preview_data: &'a [u8],
    /// Table of records describing each layer. In bilevel files using
    /// antialiasing, there will be `layer_count * aa_level` of these.
    pub layer_table: &'a [LayerHeader],
    /// Encoded data corresponding to records in `layer_table`.
    pub layer_data: Vec<&'a [u8]>,
}

/// Reference to file headers from `Layout`, which changes shape depending on
/// which file header format is being used.
pub enum Headers<'a> {
    /// File uses the split header.
    Split {
        /// Start of split header.
        header: &'a SplitHeader,
        /// First extended config record.
        ext_config: &'a ExtConfig,
        /// Second extended config record.
        ext_config2: &'a ExtConfig2,
    },
    /// File uses the omniheader.
    Omni(&'a OmniHeader),
}

/// Unified interface to data common to all header types.
impl<'a> Headers<'a> {
    /// File offset of `ImageHeader` for large preview image.
    pub fn large_preview_offset(&self) -> u32 {
        match self {
            Self::Split { header, .. } => header.large_preview_offset.get(),
            Self::Omni(header) => header.large_preview_offset.get(),
        }
    }

    /// File offset of `ImageHeader` for small preview image.
    pub fn small_preview_offset(&self) -> u32 {
        match self {
            Self::Split { header, .. } => header.small_preview_offset.get(),
            Self::Omni(header) => header.small_preview_offset.get(),
        }
    }

    /// File offset of table of `LayerHeader` records.
    pub fn layer_table_offset(&self) -> u32 {
        match self {
            Self::Split { header, .. } => header.layer_table_offset.get(),
            Self::Omni(header) => header.layer_table_offset.get(),
        }
    }

    /// Number of printed layers.
    pub fn layer_table_count(&self) -> u32 {
        match self {
            Self::Split { header, .. } => header.layer_table_count.get(),
            Self::Omni(header) => header.layer_table_count.get(),
        }
    }

    /// Number of repetitions of printed layers in the layer table.
    pub fn level_set_count(&self) -> u32 {
        match self {
            Self::Split { header, .. } => header.level_set_count.get(),
            Self::Omni(header) => header.level_set_count.get(),
        }
    }

    /// Encryption key, or 0 if none.
    pub fn encryption_key(&self) -> u32 {
        match self {
            Self::Split { header, .. } => header.encryption_key.get(),
            Self::Omni(header) => header.encryption_key.get(),
        }
    }

    /// Printer resolution in pixels along x, y axes.
    pub fn resolution(&self) -> [u32; 2] {
        match self {
            Self::Split { header, .. } => {
                [header.resolution[0].get(), header.resolution[1].get()]
            }
            Self::Omni(header) => {
                [header.resolution[0].get(), header.resolution[1].get()]
            }
        }
    }

    /// Printer output volume in mm.
    pub fn volume(&self) -> [f32; 3] {
        match self {
            Self::Split { header, .. } => [
                header.printer_out_mm[0].get(),
                header.printer_out_mm[1].get(),
                header.printer_out_mm[2].get(),
            ],
            Self::Omni(header) => [
                header.printer_out_mm[0].get(),
                header.printer_out_mm[1].get(),
                header.printer_out_mm[2].get(),
            ],
        }
    }

    /// Layer height in millimeters.
    pub fn layer_height_mm(&self) -> f32 {
        match self {
            Self::Split { header, .. } => header.layer_height_mm.get(),
            Self::Omni(header) => header.layer_height_mm.get(),
        }
    }
}

/// Errors produced by `parse_file`. These only reflect structural issues in the
/// file, since `parse_file` does very little data validation.
#[derive(Copy, Clone, Debug)]
pub enum ParseError {
    /// The file ended before the mandatory file header, or referenced a section
    /// using an offset that was past the end of the file.
    Truncated,
    /// The file's magic number was not recognized. This gets priority over
    /// other parse errors to provide better feedback if you try to parse
    /// garbage.
    BadMagic(u32),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ParseError::Truncated => f.write_str("file truncated"),
            ParseError::BadMagic(m) => write!(f, "bad magic 0x{:08x}", m),
        }
    }
}

impl std::error::Error for ParseError {}

/// Examines the structure of `buf` and parses it into a `Layout`.
///
/// This does almost no checking of the file's contents. It only ensures that
/// the file is long enough to contain the records that it says it does. In
/// particular, any compressed or encoded sections, such as preview images or
/// layer data, could be totally bogus.
///
/// This function will decline to parse any file with unrecognized magic. (TODO:
/// it would otherwise be useful for analyzing format variations.)
pub fn parse_file(buf: &[u8]) -> Result<Layout<'_>, ParseError> {
    let magic_header = parse_type::<MagicHeader>(buf, 0)?;

    // Indicate magic errors *first*, before trying a bunch of silly parsing.
    let magic = Magic::from_u32(magic_header.magic.get())
        .ok_or(ParseError::BadMagic(magic_header.magic.get()))?;

    let (headers, machine_type) = match magic.header_style() {
        HeaderStyle::Split => {
            let header = parse_type::<SplitHeader>(
                buf,
                size_of::<MagicHeader>() as u32,
            )?;
            let ext_config = parse_type_prefix::<ExtConfig>(
                buf,
                header.ext_config_offset.get(),
                header.ext_config_size.get(),
            )?;
            let ext_config2 = parse_type_prefix::<ExtConfig2>(
                buf,
                header.ext_config2_offset.get(),
                header.ext_config2_size.get(),
            )?;
            let machine_type = parse_bytes(
                buf,
                ext_config2.machine_type_offset.get(),
                ext_config2.machine_type_len.get(),
            )?;
            (
                Headers::Split {
                    header,
                    ext_config,
                    ext_config2,
                },
                machine_type,
            )
        }
        HeaderStyle::Omni => {
            let header =
                parse_type::<OmniHeader>(buf, size_of::<MagicHeader>() as u32)?;
            let machine_type = parse_bytes(
                buf,
                header.machine_type_offset.get(),
                header.machine_type_len.get(),
            )?;
            (Headers::Omni(header), machine_type)
        }
    };

    let large_preview_header =
        parse_type::<ImageHeader>(buf, headers.large_preview_offset())?;
    let small_preview_header =
        parse_type::<ImageHeader>(buf, headers.small_preview_offset())?;

    let large_preview_data = parse_bytes(
        buf,
        large_preview_header.data_offset.get(),
        large_preview_header.data_len.get(),
    )?;
    let small_preview_data = parse_bytes(
        buf,
        small_preview_header.data_offset.get(),
        small_preview_header.data_len.get(),
    )?;

    // Okay, we gots to employ some smarts here. The layer table length in the
    // header lies for antialiased images.
    let actual_layer_count =
        headers.layer_table_count() * headers.level_set_count();
    let layer_table = parse_slice::<LayerHeader>(
        buf,
        headers.layer_table_offset(),
        actual_layer_count,
    )?;

    let layer_data: Result<Vec<_>, _> = layer_table
        .iter()
        .map(|hdr| parse_bytes(buf, hdr.data_offset.get(), hdr.data_len.get()))
        .collect();
    let layer_data = layer_data?;

    Ok(Layout {
        magic: magic_header,
        header: headers,
        machine_type,
        large_preview_header,
        large_preview_data,
        small_preview_header,
        small_preview_data,
        layer_table,
        layer_data,
    })
}

fn parse_type<T: FromBytes + Unaligned>(
    buf: &[u8],
    offset: u32,
) -> Result<&T, ParseError> {
    Ok(LayoutVerified::<_, T>::new_unaligned(parse_bytes(
        buf,
        offset,
        size_of::<T>() as u32,
    )?)
    .ok_or(ParseError::Truncated)?
    .into_ref())
}

fn parse_slice<T: FromBytes + Unaligned>(
    buf: &[u8],
    offset: u32,
    len: u32,
) -> Result<&[T], ParseError> {
    Ok(LayoutVerified::<_, [T]>::new_slice_unaligned(parse_bytes(
        buf,
        offset,
        size_of::<T>() as u32 * len,
    )?)
    .ok_or(ParseError::Truncated)?
    .into_slice())
}

fn parse_type_prefix<T: FromBytes + Unaligned>(
    buf: &[u8],
    offset: u32,
    len: u32,
) -> Result<&T, ParseError> {
    Ok(
        LayoutVerified::<_, T>::new_unaligned_from_prefix(parse_bytes(
            buf, offset, len,
        )?)
        .ok_or(ParseError::Truncated)?
        .0
        .into_ref(),
    )
}

fn parse_bytes(buf: &[u8], offset: u32, len: u32) -> Result<&[u8], ParseError> {
    let offset = offset as usize;
    let end = offset.wrapping_add(len as usize);
    if offset >= buf.len() || end < offset || end > buf.len() {
        return Err(ParseError::Truncated);
    }
    Ok(&buf[offset..end])
}

/// Errors that can be produced when decoding an image.
#[cfg(feature = "image")]
#[derive(Copy, Clone, Debug)]
pub enum ImageError {
    /// The RLE-encoded image data was invalid or truncated.
    Rle(rle::RleError),
    /// RLE-encoded data kept going past the end of the expected image. This is
    /// often a sign that you've decoded the wrong or invalid data.
    TooManyPixels,
    /// RLE-encoded data ended before the end of the expected image. This is
    /// often a sign that you've decoded the wrong or invalid data.
    TooFewPixels,
}

#[cfg(feature = "image")]
impl std::fmt::Display for ImageError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Rle(e) => e.fmt(f),
            Self::TooManyPixels => f.write_str("too many pixels"),
            Self::TooFewPixels => f.write_str("too few pixels"),
        }
    }
}

#[cfg(feature = "image")]
impl std::error::Error for ImageError {}

#[cfg(feature = "image")]
impl From<rle::RleError> for ImageError {
    fn from(e: rle::RleError) -> Self {
        ImageError::Rle(e)
    }
}

/// Decodes a preview image, in the RLE12 format used by the files.
#[cfg(feature = "image")]
pub fn decode_image(
    width: u32,
    height: u32,
    data: &[u8],
) -> Result<image::ImageBuffer<image::Rgb<u8>, Vec<u8>>, ImageError> {
    let mut image = image::ImageBuffer::new(width, height);
    let mut cursor = data.iter().cloned();
    let mut putpix = image.pixels_mut();
    let mut pixels_total = 0;

    while let Some((color, len)) = rle::decode_rle15(&mut cursor)? {
        pixels_total += len;
        let pixel = image::Rgb::from([color.0, color.1, color.2]);
        for _ in 0..len {
            let dest = putpix.next().ok_or(ImageError::TooManyPixels)?;
            *dest = pixel;
        }
    }

    if pixels_total != (width * height) as usize {
        return Err(ImageError::TooFewPixels);
    }

    Ok(image)
}

/// Low-level decoding of a bilevel slice, with possible antialiasing.
///
/// This function is somewhat complex.
///
/// `stack` is a vector of iterators over *separate* RLE-encoded images. This is
/// because the antialiased bilevel format indicates different values by
/// repeatedly encoding the same image at different threshold levels.
///
/// For an image with `A`-level antialiasing and `N` printed layers, to decode
/// printed layer `X` you need to provide iterators over data for file layers
/// `X`, `X+N`, `X+2*N`, and so on through `X+(A-1)*N`.
///
/// `resolution` is the expected `[x, y]` resolution of the printer, to detect
/// corruption more quickly by limiting the decompressed size of the slice.
///
/// `emit` is invoked for each pixel with the arguments `(x, y, level)`.
pub fn decode_bilevel_slice<I>(
    mut stack: Vec<rle::RunIter<I>>,
    resolution: [u32; 2],
    mut emit: impl FnMut(u64, u64, u8),
) -> Result<(), ImageError>
where
    I: Iterator<Item = (u8, usize)>,
{
    // Theory of operation:
    //
    // We are simultaneously iterating over several bilevel images. Each level
    // records a bilevel thresholding of the same input image, with successively
    // higher thresholds. This means the first image is a strict superset of the
    // second, and the second of the third, etc.
    //
    // To do this reasonably quickly, we take iterators over the pixel stream
    // from each image (which is presumably compressed, but gets uncompressed
    // before we receive it). Starting at the highest threshold image, we check
    // for a set pixel, and, if found, skip a pixel from all lower-threshold
    // images.
    let stack = &mut stack[..];
    assert!(!stack.is_empty());

    let rx = resolution[0] as u64;
    let aa_levels = stack.len();

    let (mut x, mut y) = (0, 0);
    let mut pixels_remaining = (resolution[0] * resolution[1]) as usize;

    'outer: loop {
        let mut emitted = false;
        // Start at the most occupied level and work back.
        for level in (0..aa_levels).rev() {
            // Sample the level.
            let pixel = match stack[level].next() {
                Some(p) => p,
                None => {
                    // We've reached the end of the image; tolerate this only on
                    // the highest level (first to be processed). Otherwise it's
                    // an inconsistency.
                    if level == aa_levels - 1 {
                        break 'outer;
                    } else {
                        return Err(ImageError::TooFewPixels);
                    }
                }
            };

            // If we got a pixel, but shouldn't've, bail.
            if pixels_remaining == 0 {
                return Err(ImageError::TooManyPixels);
            }

            // Handle only occupied pixels.
            if pixel != 0 {
                // Compute occupancy fraction based on our position in the level
                // stack, and record it.
                let value = ((level + 1) * 0xFF / aa_levels) as u8;
                emit(x, y, value);
                emitted = true;
                // Ignore this pixel in all lower levels. (If we processed any
                // higher levels, they have already processed this pixel, and it
                // produced zero -- so this puts all levels at a consistent
                // position.)
                for skip in (0..level).rev() {
                    stack[skip].next().ok_or(ImageError::TooFewPixels)?;
                }
                // Stop working down the level stack, we're done with this
                // pixel.
                break;
            }
        }

        if !emitted {
            emit(x, y, 0);
        }

        // Record pixel and update coordinates.
        pixels_remaining -= 1;
        x += 1;
        if x == rx {
            x = 0;
            y += 1;
        }
    }

    if pixels_remaining > 0 {
        Err(ImageError::TooFewPixels)
    } else {
        Ok(())
    }
}

/// Decodes a multilevel (grayscale) slice, with optional encryption.
///
/// This is dramatically simpler than decoding a bilevel antialiased slice.
///
/// `data` is the encoded bytes.
///
/// `resolution` is the expected `[x, y]` resolution of the printer, to detect
/// corruption more quickly by limiting the decompressed size of the slice.
///
/// `z` is the index of the layer being decoded. This is required because it's
/// used as an initialization vector for encrypted files, and can be omitted if
/// you're not using encryption.
///
/// `key` is the encryption key, or `0` for no encryption.
///
/// `emit` is invoked for each pixel with the arguments `(x, y, level)`.
pub fn decode_multilevel_slice(
    data: &[u8],
    resolution: [u32; 2],
    z: u32,
    key: u32,
    mut emit: impl FnMut(u64, u64, u8),
) -> Result<(), ImageError> {
    // Make a copy of the data so we can decrypt it.
    let mut data = data.to_vec();
    // Decrypt if necessary.
    if key != 0 {
        crypto::crypt86(key, z, &mut data);
    }

    let rx = resolution[0] as u64;

    let (mut x, mut y) = (0, 0);
    let mut pixels_remaining = (resolution[0] * resolution[1]) as usize;
    let mut cursor = data.iter().cloned();

    while let Some((level, len)) = rle::decode_rle7(&mut cursor)? {
        if pixels_remaining < len {
            return Err(ImageError::TooManyPixels);
        }
        pixels_remaining -= len;

        for _ in 0..len {
            emit(x, y, level);
            x += 1;
            if x == rx {
                x = 0;
                y += 1;
            }
        }
    }

    if pixels_remaining > 0 {
        Err(ImageError::TooFewPixels)
    } else {
        Ok(())
    }
}

/// Decodes an encoded/encrypted image slice in phz format.
pub fn decode_phz_slice(
    data: &[u8],
    resolution: [u32; 2],
    z: u32,
    key: u32,
    mut emit: impl FnMut(u64, u64, u8),
) -> Result<(), ImageError> {
    // Make a copy of the data so we can decrypt it.
    let mut data = data.to_vec();
    // Decrypt if necessary.
    if key != 0 {
        crypto::crypt9f(key, z, &mut data);
    }

    let rx = resolution[0] as u64;

    let (mut x, mut y) = (0, 0);
    let mut pixels_remaining = (resolution[0] * resolution[1]) as usize;
    let runs = rle::decode_rle7a(data.iter().cloned());

    for run in runs {
        let (level, len) = run?;

        if pixels_remaining < len {
            return Err(ImageError::TooManyPixels);
        }
        pixels_remaining -= len;

        for _ in 0..len {
            emit(x, y, level);
            x += 1;
            if x == rx {
                x = 0;
                y += 1;
            }
        }
    }

    if pixels_remaining > 0 {
        Err(ImageError::TooFewPixels)
    } else {
        Ok(())
    }
}
