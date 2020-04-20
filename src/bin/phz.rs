//! Starting to analyze PHZ, which is similar enough that it's clearly related,
//! but still pretty different.

use std::error::Error;
use std::mem::size_of;

use byteorder::{ByteOrder, LittleEndian};
use catibo::*;
use structopt::StructOpt;
use zerocopy::{FromBytes, LayoutVerified, Unaligned};

/// Provides simple dumps of the PHZ file format, which is still being reverse
/// engineered and is probably wrong.
#[derive(StructOpt, Debug)]
#[structopt(name = "phz", max_term_width = 80)]
struct Args {
    /// File to read.
    #[structopt(parse(from_os_str))]
    input: std::path::PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::from_args();

    let input_image = std::fs::read(args.input)?;
    let header_slice = &input_image[..size_of::<PhzHeader>()];
    let lvr = LayoutVerified::<_, PhzHeader>::new_unaligned(header_slice);
    let header = match lvr {
        None => {
            eprintln!("hmmm... file not long enough for header...");
            std::process::exit(1);
        }
        Some(hdr) => hdr.into_ref(),
    };
    println!("{:#?}", header);

    let layer_table_slice = &input_image[header.layer_table_offset.get()
        as usize
        ..header.layer_table_offset.get() as usize
            + header.layer_table_count.get() as usize * 36];
    let lvr = LayoutVerified::<_, [catibo::LayerHeader]>::new_slice_unaligned(
        layer_table_slice,
    );

    let layer_table = match lvr {
        None => {
            eprintln!("hmmm... what went wrong with the layer table");
            std::process::exit(2);
        }
        Some(t) => t.into_slice(),
    };

    for (i, lhd) in layer_table.iter().enumerate() {
        //println!("# layer {}", i);
        let data_slice = &input_image[lhd.data_offset.get() as usize
            ..lhd.data_offset.get() as usize + lhd.data_len.get() as usize];
        let mut copy = data_slice.to_vec();
        catibo::crypto::crypt9f(
            header.encryption_key.get(),
            i as u32,
            &mut copy,
        );

        // Check statistical assumptions about RLE scheme
        //println!("contains 0x00: {:?}", copy.contains(&0));
        //println!("contains 0x7e: {:?}", copy.contains(&0x7e));
        //println!("contains 0x7f: {:?}", copy.contains(&0x7f));
        let decoded = decode(&copy);
        assert_eq!(
            decoded.len(),
            header.resolution[0].get() as usize
                * header.resolution[1].get() as usize
        );
        println!("layer {} checks out", i);
    }

    Ok(())
}

fn decode(data: &[u8]) -> Vec<u8> {
    // Decoder for inferred RLE scheme.
    let mut out = vec![];
    let mut color = None;
    for &byte in data {
        if byte & 0x80 == 0 {
            let run_length = usize::from(byte & 0x7F);
            let color = color.expect("run without color?");
            out.resize(out.len() + run_length, color);
        } else {
            out.push(byte << 1);
            color = Some(byte << 1);
        }
    }
    out
}

fn hexdump(data: &[u8]) {
    for line in 0.. {
        let offset = line * 16;
        let end = offset + 16;
        if offset >= data.len() {
            break;
        }
        let slice = &data[offset..data.len().min(end)];
        print!("{:08x}", offset);
        for byte in slice {
            print!(" {:02x}", *byte);
        }
        println!();
    }
}

/// Inferred PHZ header, which appears to be a remix of the original headers.
#[derive(Clone, Debug, FromBytes, Unaligned)]
#[repr(C)]
struct PhzHeader {
    magic: U32LE,
    version: U32LE,
    // deleted: printer_out_mm, unknown, overall_height
    layer_height_mm: F32LE,
    exposure_s: F32LE,
    bot_exposure_s: F32LE,
    // deleted: light off time
    bot_layer_count: U32LE, // ???
    resolution: [U32LE; 2],
    large_preview_offset: U32LE,
    layer_table_offset: U32LE,
    layer_table_count: U32LE,
    small_preview_offset: U32LE,
    print_time_s: U32LE,
    mirror: U32LE,
    // deleted: ext config reference
    // deleted: antialias level
    _unknown_38: U32LE, // one
    pwm0: U16LE,
    pwm1: U16LE,
    // deleted: encryption key (interesting)
    // deleted: ext_config2
    zeroes_40: [u8; 8],

    // originally at top
    overall_height_mm: F32LE,
    print_vol_mm: [F32LE; 3],

    // originally just above
    encryption_key: U32LE,

    // from end of ext_config
    bot_light_off_time_s: F32LE,
    light_off_time_s: F32LE, // or vice versa
    bot_layer_count_again: U32LE,

    _zero_68: [u8; 4],

    // from top of ext_config
    bot_lift_dist_mm: F32LE,
    bot_lift_speed_mmpm: F32LE,
    lift_dist_mm: F32LE,
    lift_speed_mmpm: F32LE,
    retract_speed_mmpm: F32LE,
    vol_ml: F32LE,
    mass_g: F32LE,
    cost: F32LE,

    _zero_8c: [u8; 4],

    // from ext_config2
    machine_type_offset: U32LE,
    machine_type_len: U32LE,

    // inserted
    _zero_98: [u8; 6 * 4],

    // more from ext_config2
    encryption_mode: U32LE,
    mysterious_id: U32LE,
    antialias_level: U32LE,
    software_version: U32LE,
    _zero_c0: [u8; 4 * 6],
}
