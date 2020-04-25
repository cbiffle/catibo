use std::error::Error;

use num_traits::FromPrimitive;
use rayon::prelude::*;
use structopt::StructOpt;

use catibo::Magic;

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
    /// Output file format.
    ///
    /// If omitted, the format is guessed from the file extension. The format
    /// must be provided explicitly if the output file does not have an
    /// extension, or if the extension is non-standard.
    #[structopt(short = "O", long,
        possible_values = Magic::variants(),
        case_insensitive = true)]
    output_format: Option<Magic>,
    /// File to read.
    #[structopt(parse(from_os_str))]
    input: std::path::PathBuf,
    /// File to write.
    #[structopt(parse(from_os_str))]
    output: std::path::PathBuf,
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args = Args::from_args();

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

    let input_image = std::fs::read(&args.input)?;
    let parsed = catibo::input::parse_file(&input_image)?;

    // If we're going CBDDLP <-> CTB, we need to recompress the layers and
    // potentially introduce or eliminate the bonkers antialiasing scheme.
    //
    // If we're going PHZ <-> C*, we also need to regenerate the header.
    //
    // The meaning of the fields doesn't appear to have significantly changed --
    // it's basically a permutation.
    //
    // The preview images don't need conversion, it seems.
    //
    // And so I feel like the best thing to do is to decompress all the images
    // to an unencrypted chunky 8bpp representation, and then recompress as
    // required, before doing the header transform if necessary.

    let chunky_layer_data = decompress_all_layers(&parsed)?;

    let hdr = &parsed.header;

    // Preserve the input key, unless an output key has been explicitly
    // provided.
    let out_key = args.key.unwrap_or_else(|| hdr.encryption_key());

    let mut outb = catibo::output::Builder::for_revision(output_format, 2);

    let resolution = hdr.resolution();
    // Copy over unmodified print parameters.
    match hdr {
        catibo::input::Headers::Split {
            header,
            ext_config,
            ext_config2,
        } => {
            outb.machine_type(parsed.machine_type.to_vec())
                .printer_out_mm([
                    header.printer_out_mm[0].get(),
                    header.printer_out_mm[1].get(),
                    header.printer_out_mm[2].get(),
                ])
                .resolution(resolution)
                .mirror(header.mirror.get())
                .layer_height_mm(header.layer_height_mm.get())
                .overall_height_mm(header.overall_height_mm.get())
                .bot_layer_count(header.bot_layer_count.get())
                .exposure_s(header.exposure_s.get())
                .bot_exposure_s(header.bot_exposure_s.get())
                .light_off_time_s(header.light_off_time_s.get())
                .bot_light_off_time_s(ext_config.bot_light_off_time_s.get())
                .aa_levels(ext_config2.antialias_level.get())
                .pwm_level(header.pwm_level.get())
                .bot_pwm_level(header.bot_pwm_level.get())
                .lift_dist_mm(ext_config.lift_dist_mm.get())
                .bot_lift_dist_mm(ext_config.bot_lift_dist_mm.get())
                .lift_speed_mmpm(ext_config.lift_speed_mmpm.get())
                .bot_lift_speed_mmpm(ext_config.bot_lift_speed_mmpm.get())
                .retract_speed_mmpm(ext_config.retract_speed_mmpm.get())
                .print_time_s(header.print_time_s.get())
                .print_volume_ml(ext_config.print_volume_ml.get())
                .print_mass_g(ext_config.print_mass_g.get())
                .print_price(ext_config.print_price.get());
        }
        catibo::input::Headers::Omni(header) => {
            outb.machine_type(parsed.machine_type.to_vec())
                .printer_out_mm([
                    header.printer_out_mm[0].get(),
                    header.printer_out_mm[1].get(),
                    header.printer_out_mm[2].get(),
                ])
                .resolution(resolution)
                .mirror(header.mirror.get())
                .layer_height_mm(header.layer_height_mm.get())
                .overall_height_mm(header.overall_height_mm.get())
                .bot_layer_count(header.bot_layer_count.get())
                .exposure_s(header.exposure_s.get())
                .bot_exposure_s(header.bot_exposure_s.get())
                .light_off_time_s(header.light_off_time_s.get())
                .bot_light_off_time_s(header.bot_light_off_time_s.get())
                .aa_levels(header.antialias_level.get())
                .pwm_level(header.pwm_level.get())
                .bot_pwm_level(header.bot_pwm_level.get())
                .lift_dist_mm(header.lift_dist_mm.get())
                .bot_lift_dist_mm(header.bot_lift_dist_mm.get())
                .lift_speed_mmpm(header.lift_speed_mmpm.get())
                .bot_lift_speed_mmpm(header.bot_lift_speed_mmpm.get())
                .retract_speed_mmpm(header.retract_speed_mmpm.get())
                .print_time_s(header.print_time_s.get())
                .print_volume_ml(header.print_volume_ml.get())
                .print_mass_g(header.print_mass_g.get())
                .print_price(header.print_price.get());
        }
    }

    if output_format.encryption().is_some() {
        outb.encryption_key(out_key);
    }

    // We'll just force the level set count to 1, because we currently don't
    // support antialiased cbddlp output.
    outb.level_set_count(1);
    if output_format == Magic::CBDDLP {
        outb.aa_levels(1);
    }

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

    let layers_to_add = (0..parsed.layer_table.len())
        .into_par_iter()
        .map(|i| {
            let header = &parsed.layer_table[i];

            let uncompressed = &chunky_layer_data[i];
            let cvt_data = match output_format {
                Magic::CTB => {
                    let mut compressed =
                        Vec::with_capacity(parsed.layer_data[i].len());
                    catibo::output::encode_rle7_slice(
                        uncompressed.iter().cloned().peekable(),
                        out_key,
                        i as u32,
                        &mut compressed,
                    );

                    compressed
                }
                Magic::CBDDLP => {
                    let mut compressed = Vec::with_capacity(uncompressed.len());
                    let mut iter = uncompressed.iter().cloned().peekable();
                    while let Some(rle) =
                        catibo::rle::encode_rle1(0x80, &mut iter)
                    {
                        compressed.push(rle);
                    }

                    compressed
                }
                Magic::PHZ => {
                    let mut compressed =
                        Vec::with_capacity(parsed.layer_data[i].len());
                    catibo::output::encode_rle7a_slice(
                        &uncompressed,
                        resolution[0],
                        out_key,
                        i as u32,
                        &mut compressed,
                    );

                    compressed
                }
            };

            (
                header.z.get(),
                header.exposure_s.get(),
                header.light_off_time_s.get(),
                cvt_data,
            )
        })
        .collect::<Vec<_>>();

    for (z, exp, lof, data) in layers_to_add {
        outb.layer(z, exp, lof, data);
    }
    outb.write(std::fs::File::create(args.output)?)?;

    Ok(())
}

fn format_from_ext(ext: &str) -> Option<Magic> {
    use std::str::FromStr;

    Magic::from_str(ext).ok()
}

fn decompress_all_layers(
    parsed: &catibo::input::Layout<'_>,
) -> Result<Vec<Vec<u8>>, Box<dyn Error + Sync + Send>> {
    let magic = Magic::from_u32(parsed.magic.magic.get()).unwrap();
    let [width, height] = parsed.header.resolution();
    let per_level_layer_count = parsed.header.layer_table_count() as usize;

    match magic {
        Magic::CBDDLP => (0..per_level_layer_count)
            .into_par_iter()
            .map(|i| {
                let stack = parsed.layer_data[i..]
                    .iter()
                    .step_by(per_level_layer_count)
                    .map(|data| {
                        catibo::rle::RunIter::from(catibo::rle::Rle1Iter::from(
                            data.iter().cloned(),
                        ))
                    })
                    .collect::<Vec<_>>();
                let mut data = Vec::with_capacity((width * height) as usize);
                catibo::input::decode_bilevel_slice(
                    stack,
                    [width, height],
                    |_, _, v| data.push(v),
                )?;
                Ok(data)
            })
            .collect::<Result<Vec<_>, _>>(),
        Magic::CTB => (0..per_level_layer_count)
            .into_par_iter()
            .map(|i| {
                let mut uncompressed =
                    Vec::with_capacity((width * height) as usize);
                catibo::input::decode_multilevel_slice(
                    &parsed.layer_data[i],
                    [width, height],
                    i as u32,
                    parsed.header.encryption_key(),
                    |_, _, x| uncompressed.push(x),
                )?;
                Ok(uncompressed)
            })
            .collect::<Result<Vec<_>, _>>(),
        Magic::PHZ => (0..per_level_layer_count)
            .into_par_iter()
            .map(|i| {
                let mut uncompressed =
                    Vec::with_capacity((width * height) as usize);
                catibo::input::decode_phz_slice(
                    &parsed.layer_data[i],
                    [width, height],
                    i as u32,
                    parsed.header.encryption_key(),
                    |_, _, x| uncompressed.push(x),
                )?;
                Ok(uncompressed)
            })
            .collect::<Result<Vec<_>, _>>(),
    }
}
