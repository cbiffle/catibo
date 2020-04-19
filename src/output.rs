//! Writes files in supported formats from high-level descriptions.

use std::io;
use std::mem::size_of;

use zerocopy::AsBytes;

use crate::crypto;
use crate::rle;
use crate::{
    ExtConfig, ExtConfig2, ImageHeader, LayerHeader, Magic, MagicHeader,
    SplitHeader, F32LE, U16LE, U32LE,
};

/// Quantizes and encodes 8bpp samples into an RLE7-encoded slice with optional
/// encryption.
///
/// `data` is a peekable iterator over the samples.
///
/// `key` is the encryption key, or `0` for no encryption.
///
/// `z` is the index of the slice/layer being encoded. This is required because
/// it's used as an initialization vector for the cipher; if you're not using
/// encryption you can omit this.
///
/// `out` is a `Vec` where encoded/encrypted output will be appended.
pub fn encode_rle7_slice<I>(
    mut data: std::iter::Peekable<I>,
    key: u32,
    z: u32,
    out: &mut Vec<u8>,
) where
    I: Iterator<Item = u8>,
{
    while let Some(run) = rle::encode_rle7(&mut data) {
        match run {
            rle::Run7::R1(x) => out.push(x),
            rle::Run7::R2(xs) => out.extend_from_slice(&xs),
            rle::Run7::R3(xs) => out.extend_from_slice(&xs),
            rle::Run7::R4(xs) => out.extend_from_slice(&xs),
            rle::Run7::R5(xs) => out.extend_from_slice(&xs),
        }
    }
    if key != 0 {
        crypto::crypt86(key, z, out);
    }
}

/// Encodes an RGB `ImageBuffer` into the format used for preview images.
#[cfg(feature = "image")]
pub fn encode_image<C>(image: &image::ImageBuffer<image::Rgb<u8>, C>) -> Vec<u8>
where
    C: core::ops::Deref<Target = [u8]>,
{
    use byteorder::{LittleEndian, WriteBytesExt};

    let mut pixels = image.pixels().map(|r| (r[0], r[1], r[2])).peekable();
    let mut encoded = vec![];
    let mut cursor = io::Cursor::new(&mut encoded);
    while let Some(run) = rle::encode_rle15(&mut pixels) {
        match run {
            rle::Run12::Single(val) => {
                cursor.write_u16::<LittleEndian>(val).unwrap();
            }
            rle::Run12::Double(val0, val1) => {
                cursor.write_u16::<LittleEndian>(val0).unwrap();
                cursor.write_u16::<LittleEndian>(val1).unwrap();
            }
        }
    }
    encoded
}

/// Collects information needed to generate a file.
#[derive(Clone, Debug)]
pub struct Builder {
    magic: Magic,
    version: u32,

    printer_out_mm: [F32LE; 3],
    mirror: U32LE,
    layer_height_mm: F32LE,
    overall_height_mm: F32LE,
    exposure_s: F32LE,
    bot_exposure_s: F32LE,
    light_off_time_s: F32LE,
    bot_layer_count: U32LE,
    resolution: [U32LE; 2],
    print_time_s: U32LE,
    pwm_level: U16LE,
    bot_pwm_level: U16LE,

    large_preview: Image,
    small_preview: Image,

    ext_config: ExtConfig,

    machine_type: Vec<u8>,
    encryption_mode: u32,
    encryption_key: U32LE,

    level_set_count: u32,
    aa_levels: u32,

    layers: Vec<Layer>,
}

#[derive(Clone, Debug, Default)]
struct Image {
    width: u32,
    height: u32,
    data: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
struct Layer {
    z: f32,
    exposure_s: f32,
    light_off_time_s: f32,
    data: Vec<u8>,
}

impl Builder {
    /// Creates a builder for a file with the given flavor.
    ///
    /// The `version` is, in practice, always 2.
    pub fn for_revision(magic: Magic, version: u32) -> Self {
        let encryption_mode = match magic {
            Magic::PlanarLevelSet => 0,
            Magic::Multilevel => 0xF,
            Magic::PlanarLevelSet2 => unimplemented!(),
        };
        Self {
            magic,
            version,
            printer_out_mm: [F32LE::default(); 3],
            mirror: U32LE::new(1),
            layer_height_mm: F32LE::default(),
            overall_height_mm: F32LE::default(),
            exposure_s: F32LE::default(),
            bot_exposure_s: F32LE::default(),
            light_off_time_s: F32LE::default(),
            bot_layer_count: U32LE::default(),
            resolution: [U32LE::default(); 2],
            print_time_s: U32LE::default(),
            pwm_level: U16LE::default(),
            bot_pwm_level: U16LE::default(),
            large_preview: Image::default(),
            small_preview: Image::default(),
            ext_config: ExtConfig::default(),
            machine_type: vec![],
            encryption_mode,
            encryption_key: U32LE::default(),
            level_set_count: 1,
            aa_levels: 1,
            layers: vec![],
        }
    }

    /// Updates the machine type that will be recorded in the file.
    pub fn machine_type(&mut self, mt: Vec<u8>) -> &mut Self {
        self.machine_type = mt;
        self
    }

    /// Updates the mirroring setting that will be recorded.
    ///
    /// `0` is normal, `1` is `LCD_mirror` (the default).
    pub fn mirror(&mut self, x: u32) -> &mut Self {
        self.mirror = U32LE::new(x);
        self
    }

    /// Updates the encryption mode that will be recorded.
    ///
    /// This field is poorly understood; it defaults to 0 for file formats that
    /// have not been observed using encryption, and `0xF` for those that have.
    pub fn encryption_mode(&mut self, x: u32) -> &mut Self {
        self.encryption_mode = x;
        self
    }

    /// Updates the file-level encryption key that will be recorded.
    ///
    /// This key is not secret; it's recorded right in the file header for all
    /// to see. `0` means no encryption.
    pub fn encryption_key(&mut self, x: u32) -> &mut Self {
        self.encryption_key = U32LE::new(x);
        self
    }

    /// Updates the number of times each level set (layer data) is repeated.
    ///
    /// For 1bpp representations, this should match the `aa_levels`, which
    /// should in turn match how often layers are repeated.
    ///
    /// For deeper representations this should not be changed from the default
    /// of 1.
    pub fn level_set_count(&mut self, x: u32) -> &mut Self {
        self.level_set_count = x;
        self
    }
    /// Updates the user antialiasing setting that will be recorded.
    ///
    /// Doing this properly requires some care -- for 1bpp representations, this
    /// should match the `level_set_count`, which should in turn match how often
    /// layers are repeated. For deeper representations, this doesn't mean much.
    pub fn aa_levels(&mut self, x: u32) -> &mut Self {
        self.aa_levels = x;
        self
    }

    /// Updates the layer height in millimeters.
    pub fn layer_height_mm(&mut self, x: f32) -> &mut Self {
        self.layer_height_mm = F32LE::new(x);
        self
    }

    /// Updates the overall printed model height in millimeters.
    pub fn overall_height_mm(&mut self, x: f32) -> &mut Self {
        self.overall_height_mm = F32LE::new(x);
        self
    }

    /// Updates the exposure time in seconds for normal layers.
    pub fn exposure_s(&mut self, x: f32) -> &mut Self {
        self.exposure_s = F32LE::new(x);
        self
    }

    /// Updates the exposure time in seconds for bottom layers.
    pub fn bot_exposure_s(&mut self, x: f32) -> &mut Self {
        self.bot_exposure_s = F32LE::new(x);
        self
    }

    /// Updates the number of layers considered to be "bottom."
    pub fn bot_layer_count(&mut self, x: u32) -> &mut Self {
        self.bot_layer_count = U32LE::new(x);
        self.ext_config.bot_layer_count = U32LE::new(x);
        self
    }

    /// Updates the light-off time, in seconds, after normal layers.
    pub fn light_off_time_s(&mut self, x: f32) -> &mut Self {
        self.light_off_time_s = F32LE::new(x);
        self.ext_config.light_off_time_s = F32LE::new(x);
        self
    }

    /// Updates the light-off time, in seconds, after bottom layers.
    pub fn bot_light_off_time_s(&mut self, x: f32) -> &mut Self {
        self.ext_config.bot_light_off_time_s = F32LE::new(x);
        self
    }

    /// Updates the estimate of the print duration, in seconds.
    pub fn print_time_s(&mut self, x: u32) -> &mut Self {
        self.print_time_s = U32LE::new(x);
        self
    }

    /// Updates the backlight PWM setting for normal layers.
    pub fn pwm_level(&mut self, x: u16) -> &mut Self {
        self.pwm_level = U16LE::new(x);
        self
    }

    /// Updates the backlight PWM setting for bottom layers.
    pub fn bot_pwm_level(&mut self, x: u16) -> &mut Self {
        self.bot_pwm_level = U16LE::new(x);
        self
    }

    /// Updates the lift distance, in millimeters, for the platform to withdraw
    /// after printing a bottom layer.
    pub fn bot_lift_dist_mm(&mut self, x: f32) -> &mut Self {
        self.ext_config.bot_lift_dist_mm = F32LE::new(x);
        self
    }

    /// Updates the lift speed, in millimeters per minute, for the platform to
    /// withdraw after printing a bottom layer.
    pub fn bot_lift_speed_mmpm(&mut self, x: f32) -> &mut Self {
        self.ext_config.bot_lift_speed_mmpm = F32LE::new(x);
        self
    }

    /// Updates the lift distance, in millimeters, for the platform to withdraw
    /// after printing a normal layer.
    pub fn lift_dist_mm(&mut self, x: f32) -> &mut Self {
        self.ext_config.lift_dist_mm = F32LE::new(x);
        self
    }

    /// Updates the lift speed, in millimeters per minute, for the platform to
    /// withdraw after printing a normal layer.
    pub fn lift_speed_mmpm(&mut self, x: f32) -> &mut Self {
        self.ext_config.lift_speed_mmpm = F32LE::new(x);
        self
    }

    /// Updates the speed, in millimeters per minute, for the platform to
    /// reapproach the vat after lifting.
    pub fn retract_speed_mmpm(&mut self, x: f32) -> &mut Self {
        self.ext_config.retract_speed_mmpm = F32LE::new(x);
        self
    }

    /// Updates the estimated volume of resin required, in milliliters.
    pub fn print_volume_ml(&mut self, x: f32) -> &mut Self {
        self.ext_config.print_volume_ml = F32LE::new(x);
        self
    }

    /// Updates the estimated mass of resin required, in grams.
    pub fn print_mass_g(&mut self, x: f32) -> &mut Self {
        self.ext_config.print_mass_g = F32LE::new(x);
        self
    }

    /// Updates the estimated cost of resin required, in whatever currency unit
    /// the user has currently selected. (Currency units are not stored in the
    /// file.)
    pub fn print_price(&mut self, x: f32) -> &mut Self {
        self.ext_config.print_price = F32LE::new(x);
        self
    }

    /// Updates the expected output volume of the printer, measured in
    /// millimeters along the `[x, y, z]` axes.
    pub fn printer_out_mm(&mut self, vol: [f32; 3]) -> &mut Self {
        self.printer_out_mm =
            [F32LE::new(vol[0]), F32LE::new(vol[1]), F32LE::new(vol[2])];
        self
    }

    /// Updates the resolution of the printer, in pixels along `[x, y`].
    pub fn resolution(&mut self, x: [u32; 2]) -> &mut Self {
        self.resolution = [U32LE::new(x[0]), U32LE::new(x[1])];
        self
    }

    /// Updates the (encoded) large preview image.
    pub fn large_preview(
        &mut self,
        width: u32,
        height: u32,
        data: Vec<u8>,
    ) -> &mut Self {
        self.large_preview = Image {
            width,
            height,
            data,
        };
        self
    }

    /// Updates the (encoded) small preview image.
    pub fn small_preview(
        &mut self,
        width: u32,
        height: u32,
        data: Vec<u8>,
    ) -> &mut Self {
        self.small_preview = Image {
            width,
            height,
            data,
        };
        self
    }

    /// Appends a layer.
    pub fn layer(
        &mut self,
        z: f32,
        exposure_s: f32,
        light_off_time_s: f32,
        data: Vec<u8>,
    ) -> &mut Self {
        self.layers.push(Layer {
            z,
            exposure_s,
            light_off_time_s,
            data,
        });
        self
    }

    /// Gathers up all the information provided to the builder and generates a
    /// file thru `out`.
    pub fn write(&self, mut out: impl io::Write + io::Seek) -> io::Result<()> {
        // Seek past file header.
        out.seek(io::SeekFrom::Start(
            (size_of::<MagicHeader>() + size_of::<SplitHeader>()) as u64,
        ))?;

        // Write large preview.
        let large_preview_offset =
            Self::write_encoded_image(&self.large_preview, &mut out)?;

        // Write small preview.
        let small_preview_offset =
            Self::write_encoded_image(&self.small_preview, &mut out)?;

        // Write ext_config record
        let ext_config_offset = Self::write_record(&self.ext_config, &mut out)?;

        // Write ext_config2, which contains subordinate fields referenced by
        // offset.
        let ext_config2_offset = out.seek(io::SeekFrom::Current(0))?;
        let machine_type_offset =
            out.seek(io::SeekFrom::Current(size_of::<ExtConfig2>() as i64))?;
        out.write_all(&self.machine_type)?;
        out.seek(io::SeekFrom::Start(ext_config2_offset))?;
        Self::write_record(
            &ExtConfig2 {
                machine_type_offset: U32LE::new(machine_type_offset as u32),
                machine_type_len: U32LE::new(self.machine_type.len() as u32),
                encryption_mode: U32LE::new(self.encryption_mode),
                antialias_level: U32LE::new(self.aa_levels),
                ..ExtConfig2::default()
            },
            &mut out,
        )?;
        let layer_table_offset = out.seek(io::SeekFrom::Start(
            machine_type_offset + self.machine_type.len() as u64,
        ))?;

        // Leave a hole for the layer table.
        out.seek(io::SeekFrom::Current(
            (size_of::<LayerHeader>() * self.layers.len()) as i64,
        ))?;

        // Collect layer data characteristics.
        let data_locations = {
            let mut locs = vec![];
            let mut offset = out.seek(io::SeekFrom::Current(0))?;
            for layer in &self.layers {
                locs.push((offset, layer.data.len()));
                out.write_all(&layer.data)?;
                offset += layer.data.len() as u64;
            }
            locs
        };

        // Seek back and emit table.
        out.seek(io::SeekFrom::Start(layer_table_offset))?;
        for (layer, (offset, size)) in self.layers.iter().zip(&data_locations) {
            let header = LayerHeader {
                z: F32LE::new(layer.z),
                exposure_s: F32LE::new(layer.exposure_s),
                light_off_time_s: F32LE::new(layer.light_off_time_s),
                data_offset: U32LE::new(*offset as u32),
                data_len: U32LE::new(*size as u32),
                ..LayerHeader::default()
            };
            out.write_all(header.as_bytes())?;
        }

        // Write file header.
        out.seek(io::SeekFrom::Start(0))?;

        let magic_header = MagicHeader {
            magic: U32LE::new(self.magic as u32),
            version: U32LE::new(self.version),
        };
        let split_header = Box::new(SplitHeader {
            large_preview_offset: U32LE::new(large_preview_offset as u32),
            small_preview_offset: U32LE::new(small_preview_offset as u32),

            ext_config_offset: U32LE::new(ext_config_offset as u32),
            ext_config_size: U32LE::new(size_of::<ExtConfig>() as u32),

            ext_config2_offset: U32LE::new(ext_config2_offset as u32),
            ext_config2_size: U32LE::new(size_of::<ExtConfig2>() as u32),

            layer_table_offset: U32LE::new(layer_table_offset as u32),
            layer_table_count: U32LE::new(
                self.layers.len() as u32 / self.aa_levels,
            ),

            printer_out_mm: self.printer_out_mm,
            mirror: self.mirror,
            layer_height_mm: self.layer_height_mm,
            overall_height_mm: self.overall_height_mm,
            exposure_s: self.exposure_s,
            bot_exposure_s: self.bot_exposure_s,
            light_off_time_s: self.light_off_time_s,
            bot_layer_count: self.bot_layer_count,
            resolution: self.resolution,
            print_time_s: self.print_time_s,
            pwm_level: self.pwm_level,
            bot_pwm_level: self.bot_pwm_level,
            encryption_key: self.encryption_key,

            level_set_count: U32LE::new(self.level_set_count),

            ..SplitHeader::default()
        });
        out.write_all(magic_header.as_bytes())?;
        out.write_all(split_header.as_bytes())?;

        Ok(())
    }

    fn write_record(
        record: &impl AsBytes,
        mut out: impl io::Write + io::Seek,
    ) -> io::Result<u64> {
        let offset = out.seek(io::SeekFrom::Current(0))?;
        out.write_all(record.as_bytes())?;
        Ok(offset)
    }

    fn write_encoded_image(
        image: &Image,
        mut out: impl io::Write + io::Seek,
    ) -> io::Result<u64> {
        let header_offset = out.seek(io::SeekFrom::Current(0))?;
        let data_offset = header_offset + size_of::<ImageHeader>() as u64;
        let header = Box::new(ImageHeader {
            size: [U32LE::new(image.width), U32LE::new(image.height)],
            data_len: U32LE::new(image.data.len() as u32),
            data_offset: U32LE::new(data_offset as u32),
            ..ImageHeader::default()
        });
        out.write_all(header.as_bytes())?;
        out.write_all(&image.data)?;
        Ok(header_offset)
    }
}
