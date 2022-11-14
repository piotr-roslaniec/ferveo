use std::fs::{create_dir_all, OpenOptions};
use std::io::prelude::*;
use std::path::Path;

pub fn benchmark_setup(
    threshold: usize,
    shares_num: usize,
    num_entities: usize,
    pubkey_shares_len: usize,
    privkey_shares_len: usize,
    pubkey_share_serialized_size: usize,
    privkey_share_serialized_size: usize,
    ftt_domain_size: usize,
) {
    let A_len = pubkey_shares_len;
    let Y_len = privkey_shares_len;

    let A_size_bytes = A_len * pubkey_share_serialized_size;
    let Y_size_bytes = Y_len * privkey_share_serialized_size;

    let A_size_bytes_per_share = A_size_bytes / shares_num;
    let Y_size_bytes_per_share = Y_size_bytes / shares_num;

    let A_size_bytes_per_threshold = A_size_bytes / threshold;
    let Y_size_bytes_per_threshold = Y_size_bytes / threshold;

    let A_size_bytes_per_entity = A_size_bytes / num_entities;
    let Y_size_bytes_per_entity = Y_size_bytes / num_entities;

    let dir_path = Path::new("/tmp/benchmark_setup");
    create_dir_all(&dir_path).unwrap();

    let file_path = dir_path.join("results.md");
    eprintln!("Saving setup results to file: {}", file_path.display());

    if !file_path.exists() {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&file_path)
            .unwrap();

        writeln!(
            file,
            "|threshold|shares_num|num_entities|A_len|Y_len|A_size_bytes|Y_size_bytes|A_size_bytes_per_share|Y_size_bytes_per_share|A_size_bytes_per_threshold|Y_size_bytes_per_threshold|A_size_bytes_per_entity|Y_size_bytes_per_entity|ftt_domain_size|",
        )
        .unwrap();

        writeln!(
            file,
            "|---------|----------|------------|-----|-----|------------|------------|-----------------------|---------------------|--------------------------|---------------------------|-----------------------|-----------------------|----------|",
        )
        .unwrap();
    }

    let mut file = OpenOptions::new().append(true).open(&file_path).unwrap();

    writeln!(
        file,
        "|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|",
        threshold,
        shares_num,
        num_entities,
        A_len,
        Y_len,
        A_size_bytes,
        Y_size_bytes,
        A_size_bytes_per_share,
        Y_size_bytes_per_share,
        A_size_bytes_per_threshold,
        Y_size_bytes_per_threshold,
        A_size_bytes_per_entity,
        Y_size_bytes_per_entity,
        ftt_domain_size,
    )
    .unwrap();
}
