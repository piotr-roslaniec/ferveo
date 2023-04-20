use std::{
    collections::BTreeSet,
    fs::{create_dir_all, OpenOptions},
    io::prelude::*,
    path::PathBuf,
};

use ark_bls12_381::G1Affine;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use itertools::iproduct;
use rand::prelude::StdRng;
use rand_core::SeedableRng;

const OUTPUT_DIR_PATH: &str = "/tmp/benchmark_setup";
const OUTPUT_FILE_NAME: &str = "arkworks_results.md";

pub fn create_or_truncate_output_file() -> std::io::Result<()> {
    let file_path = PathBuf::from(OUTPUT_DIR_PATH).join(OUTPUT_FILE_NAME);
    eprintln!("Creating output file at {}", file_path.display());

    let dir_path = PathBuf::from(OUTPUT_DIR_PATH);
    create_dir_all(dir_path).unwrap();

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)?;
    file.sync_all()?;

    writeln!(
        file,
        "|n of elements|type of element|serialized size in bytes|",
    )?;
    writeln!(file, "|---|---|---|")
}

pub fn save_data(
    n_of_elements: usize,
    type_of_element: &str,
    serialized_size_in_bytes: usize,
) {
    let file_path = PathBuf::from(OUTPUT_DIR_PATH).join(OUTPUT_FILE_NAME);

    eprintln!("Appending to file: {}", file_path.display());
    let mut file = OpenOptions::new().append(true).open(&file_path).unwrap();
    writeln!(
        file,
        "{}|{}|{}|",
        n_of_elements, type_of_element, serialized_size_in_bytes
    )
    .unwrap();
}

fn main() {
    let rng = &mut StdRng::seed_from_u64(0);

    create_or_truncate_output_file().unwrap();

    let n_of_elements = [1, 10, 100];
    let elements = ["G1"];

    // Create benchmark parameters without duplicates
    let configs = iproduct!(&n_of_elements, &elements)
        .map(|(n, element)| (n, element))
        .collect::<BTreeSet<_>>();

    println!("Running benchmarks for {:?}", configs);

    for (n, element) in configs {
        println!("number_of_elements: {}, type_of_elements: {}", n, element);

        let g1_affine =
            (0..*n).map(|_| G1Affine::rand(rng)).collect::<Vec<_>>();
        let mut g1_affine_uncompressed = Vec::new();
        CanonicalSerialize::serialize_uncompressed(
            &g1_affine,
            &mut g1_affine_uncompressed,
        )
        .unwrap();
        save_data(
            *n as usize,
            &format!("{}-{}", element, "affine-uncompressed"),
            g1_affine_uncompressed.len(),
        );

        let g1_affine =
            (0..*n).map(|_| G1Affine::rand(rng)).collect::<Vec<_>>();
        let mut g1_affine_compressed = Vec::new();
        CanonicalSerialize::serialize_compressed(
            &g1_affine,
            &mut g1_affine_compressed,
        )
        .unwrap();
        save_data(
            *n as usize,
            &format!("{}-{}", element, "affine-compressed"),
            g1_affine_compressed.len(),
        );
    }
}
