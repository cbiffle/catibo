use std::error::Error;

use structopt::StructOpt;

/// Extracts and prints header information from supported volumetric file types.
#[derive(StructOpt, Debug)]
#[structopt(name = "catibo-inspect", max_term_width = 80)]
struct Args {
    /// File to read.
    #[structopt(parse(from_os_str))]
    input: std::path::PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();

    let input_image = std::fs::read(args.input)?;
    let parsed = catibo::input::parse_file(&input_image)?;

    match parsed.header {
        catibo::input::Headers::Split {
            header,
            ext_config,
            ext_config2,
        } => {
            println!("--- file header ---");
            println!("{:#x?}", header);
            println!("--- ext_config ---");
            println!("{:#x?}", ext_config);
            println!("--- ext_config2 ---");
            println!("{:#x?}", ext_config2);
        }
        catibo::input::Headers::Omni(omni) => {
            println!("--- unified file header ---");
            println!("{:#x?}", omni);
        }
    }

    println!("--- machine type ---");
    if let Ok(s) = std::str::from_utf8(&parsed.machine_type) {
        println!("{}", s);
    } else {
        println!("{:x?}", parsed.machine_type);
    }
    println!("--- large preview image ---");
    println!("{:#x?}", parsed.large_preview_header);
    println!("--- small preview image ---");
    println!("{:#x?}", parsed.small_preview_header);
    println!("--- layer table ---");
    for (i, layer) in parsed.layer_table.iter().enumerate() {
        println!("{}: {:#x?}", i, layer);
    }

    Ok(())
}
