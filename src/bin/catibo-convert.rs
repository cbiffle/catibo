use std::error::Error;

use clap::arg_enum;
use structopt::StructOpt;

arg_enum! {
    #[allow(non_camel_case_types)]
    #[derive(Copy, Clone, Debug, PartialEq)]
    enum Format {
        ctb,
        cbddlp,
    }
}

impl Format {
    fn uses_encryption(self) -> bool {
        self == Format::ctb
    }
}

impl From<Format> for catibo::Magic {
    fn from(f: Format) -> Self {
        match f {
            Format::ctb => catibo::Magic::Multilevel,
            Format::cbddlp => catibo::Magic::PlanarLevelSet,
        }
    }
}

/// Performs format conversions for supported 3D volumetric file types.
#[derive(StructOpt, Debug)]
#[structopt(name = "catibo-convert", max_term_width = 80)]
struct Args {
    /// Output encryption key override, or 0 to disable output encryption.
    ///
    /// Must be a 32-bit integer. If this option isn't present, the encryption
    /// key from the input (if any) will be reused. Ignored if the output format
    /// does not support encryption.
    #[structopt(long)]
    key: Option<u32>,
    /// Input file format.
    ///
    /// If omitted, the format is guessed from the file extension. The format
    /// must be provided explicitly if the input file does not have an
    /// extension, or if the extension is non-standard.
    #[structopt(short = "I", long, possible_values = &Format::variants(),
        case_insensitive = true)]
    input_format: Option<Format>,
    /// Output file format.
    ///
    /// If omitted, the format is guessed from the file extension. The format
    /// must be provided explicitly if the output file does not have an
    /// extension, or if the extension is non-standard.
    #[structopt(short = "O", long, possible_values = &Format::variants(),
        case_insensitive = true)]
    output_format: Option<Format>,
    /// File to read.
    #[structopt(parse(from_os_str))]
    input: std::path::PathBuf,
    /// File to write.
    #[structopt(parse(from_os_str))]
    output: std::path::PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();

    let input_format = args
        .input_format
        .or_else(|| format_from_ext(args.input.extension()?.to_str()?))
        .unwrap_or_else(|| {
            eprintln!(
                "input file must have a recognized extension, or \
            format must be specified"
            );
            std::process::exit(1);
        });

    let output_format = args
        .output_format
        .or_else(|| format_from_ext(args.output.extension()?.to_str()?))
        .unwrap_or_else(|| {
            eprintln!(
                "output file must have a recognized extension, or \
            format must be specified"
            );
            std::process::exit(1);
        });

    let input_image = std::fs::read(args.input)?;
    let parsed = catibo::input::parse_file(&input_image)?;
    let (hdr, ext_config) = match parsed.header {
        catibo::input::Headers::Split {
            header, ext_config, ..
        } => (header, ext_config),
        _ => unimplemented!(),
    };

    // Preserve the input key, unless an output key has been explicitly
    // provided.
    let out_key = args.key.unwrap_or_else(|| hdr.encryption_key.get());

    let mut outb =
        catibo::output::Builder::for_revision(output_format.into(), 2);

    // Copy over unmodified print parameters.
    let resolution = [hdr.resolution[0].get(), hdr.resolution[1].get()];
    outb.machine_type(parsed.machine_type.to_vec())
        .printer_out_mm([
            hdr.printer_out_mm[0].get(),
            hdr.printer_out_mm[1].get(),
            hdr.printer_out_mm[2].get(),
        ])
        .resolution(resolution)
        .mirror(hdr.mirror.get())
        .layer_height_mm(hdr.layer_height_mm.get())
        .overall_height_mm(hdr.overall_height_mm.get())
        .bot_layer_count(hdr.bot_layer_count.get())
        .exposure_s(hdr.exposure_s.get())
        .bot_exposure_s(hdr.bot_exposure_s.get())
        .light_off_time_s(hdr.light_off_time_s.get())
        .bot_light_off_time_s(ext_config.bot_light_off_time_s.get())
        .pwm_level(hdr.pwm_level.get())
        .bot_pwm_level(hdr.bot_pwm_level.get())
        .lift_dist_mm(ext_config.lift_dist_mm.get())
        .bot_lift_dist_mm(ext_config.bot_lift_dist_mm.get())
        .lift_speed_mmpm(ext_config.lift_speed_mmpm.get())
        .bot_lift_speed_mmpm(ext_config.bot_lift_speed_mmpm.get())
        .retract_speed_mmpm(ext_config.retract_speed_mmpm.get())
        .print_time_s(hdr.print_time_s.get())
        .print_volume_ml(ext_config.print_volume_ml.get())
        .print_mass_g(ext_config.print_mass_g.get())
        .print_price(ext_config.print_price.get());

    if output_format.uses_encryption() {
        outb.encryption_key(out_key);
    }

    // Adjust settings based on target format.
    let in_ls_count = hdr.level_set_count.get();
    let out_ls_count = match (input_format, output_format) {
        (Format::cbddlp, Format::cbddlp) => in_ls_count,
        (Format::ctb, Format::cbddlp) => 1,
        (_, Format::ctb) => 1,
    };
    outb.level_set_count(out_ls_count);

    // Preview image format is consistent across all format variations currently
    // known, so we can copy it directly without decompressing.
    outb.large_preview(
        parsed.large_preview_header.size[0].get(),
        parsed.large_preview_header.size[1].get(),
        parsed.large_preview_data.to_vec(),
    );
    outb.small_preview(
        parsed.small_preview_header.size[0].get(),
        parsed.small_preview_header.size[1].get(),
        parsed.small_preview_data.to_vec(),
    );

    for i in 0..parsed.layer_table.len() {
        let header = &parsed.layer_table[i];

        let per_level_layer_count =
            parsed.layer_data.len() / in_ls_count as usize;

        let cvt_data = match (input_format, output_format) {
            (Format::cbddlp, Format::ctb) => {
                let stack = parsed.layer_data[i..]
                    .iter()
                    .step_by(per_level_layer_count)
                    .map(|data| {
                        catibo::rle::RunIter::from(catibo::rle::Rle1Iter::from(
                            data.iter().cloned(),
                        ))
                    })
                    .collect::<Vec<_>>();
                let mut uncompressed = Vec::with_capacity(
                    (resolution[0] * resolution[1]) as usize,
                );
                catibo::input::decode_bilevel_slice(
                    stack,
                    resolution,
                    |_, _, v| uncompressed.push(v),
                )?;
                let mut compressed =
                    Vec::with_capacity(parsed.layer_data[i].len());
                catibo::output::encode_rle7_slice(
                    uncompressed.into_iter().peekable(),
                    out_key,
                    i as u32,
                    &mut compressed,
                );

                compressed
            }
            (Format::ctb, Format::cbddlp) => {
                let mut uncompressed = Vec::with_capacity(
                    (resolution[0] * resolution[1]) as usize,
                );
                catibo::input::decode_multilevel_slice(
                    &parsed.layer_data[i],
                    resolution,
                    i as u32,
                    hdr.encryption_key.get(),
                    |_, _, x| uncompressed.push(x),
                )?;
                let mut compressed = Vec::with_capacity(uncompressed.len());
                let mut iter = uncompressed.into_iter().peekable();
                while let Some(rle) = catibo::rle::encode_rle1(0x80, &mut iter)
                {
                    compressed.push(rle);
                }

                compressed
            }
            // Special case for copying over CTB layer data with
            // reencryption only, no recompression.
            (Format::ctb, Format::ctb) if args.key.is_some() => {
                let mut buf = parsed.layer_data[i].to_vec();
                let in_key = hdr.encryption_key.get();
                if in_key != 0 {
                    catibo::crypto::crypt86(
                        hdr.encryption_key.get(),
                        i as u32,
                        &mut buf,
                    );
                }
                if out_key != 0 {
                    catibo::crypto::crypt86(out_key, i as u32, &mut buf);
                }
                buf
            }

            (a, b) => {
                // Check that I haven't missed a case
                assert_eq!(a, b);

                parsed.layer_data[i].to_vec()
            }
        };

        outb.layer(
            header.z.get(),
            header.exposure_s.get(),
            header.light_off_time_s.get(),
            cvt_data,
        );
    }

    outb.write(std::fs::File::create(args.output)?)?;

    Ok(())
}

fn format_from_ext(ext: &str) -> Option<Format> {
    use std::str::FromStr;

    Format::from_str(ext).ok()
}
