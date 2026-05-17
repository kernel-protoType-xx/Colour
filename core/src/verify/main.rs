/// Generates a fresh ML-DSA-87 + SPHINCS+-256 keypair.
/// Writes keys to ~/.colour-shield/keys/
fn cmd_keygen() {
    let dir = key_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        let result = KeygenResult {
            success: false,
            mldsa_pk_path:   String::new(),
            mldsa_sk_path:   String::new(),
            sphincs_pk_path: String::new(),
            sphincs_sk_path: String::new(),
            error: Some(format!("Cannot create key directory: {}", e)),
        };
        println!("{}", serde_json::to_string(&result).unwrap());
        process::exit(1);
    }

    // Generate ML-DSA-87 keypair
    let (mldsa_pk, mldsa_sk) = mldsa87::keypair();

    // Generate SPHINCS+-256 keypair
    let (sphincs_pk, sphincs_sk) = sphincssha2256ssimple::keypair();

    // Write keys to disk
    let writes = [
        (mldsa_pk_path(),   mldsa_pk.as_bytes()),
        (mldsa_sk_path(),   mldsa_sk.as_bytes()),
        (sphincs_pk_path(), sphincs_pk.as_bytes()),
        (sphincs_sk_path(), sphincs_sk.as_bytes()),
    ];

    for (path, bytes) in &writes {
        if let Err(e) = std::fs::write(path, bytes) {
            let result = KeygenResult {
                success: false,
                mldsa_pk_path:   mldsa_pk_path().display().to_string(),
                mldsa_sk_path:   mldsa_sk_path().display().to_string(),
                sphincs_pk_path: sphincs_pk_path().display().to_string(),
                sphincs_sk_path: sphincs_sk_path().display().to_string(),
                error: Some(format!("Cannot write {}: {}", path.display(), e)),
            };
            println!("{}", serde_json::to_string(&result).unwrap());
            process::exit(1);
        }
    }

    let result = KeygenResult {
        success:         true,
        mldsa_pk_path:   mldsa_pk_path().display().to_string(),
        mldsa_sk_path:   mldsa_sk_path().display().to_string(),
        sphincs_pk_path: sphincs_pk_path().display().to_string(),
        sphincs_sk_path: sphincs_sk_path().display().to_string(),
        error:           None,
    };

    println!("{}", serde_json::to_string(&result).unwrap());
}

/// Health check — verifies the binary and keys are operational.
fn cmd_health() {
    let result = HealthResult {
        healthy:          true,
        version:          "colour-core/0.1.0".to_string(),
        algorithms:       vec![
            "ML-DSA-87".to_string(),
            "SPHINCS+-SHA2-256s".to_string(),
            "BLAKE3".to_string(),
            "SHA-256".to_string(),
        ],
        keys_present:     keys_present(),
        registry_present: registry_path().exists(),
        error:            None,
    };
    println!("{}", serde_json::to_string(&result).unwrap());
}

// ── Arg parsing ───────────────────────────────────────────────────────────────

fn get_flag<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("colour-core: post-quantum package verification");
        eprintln!("");
        eprintln!("Commands:");
        eprintln!("  verify  --package <name> --version <ver> --integrity <hash>");
        eprintln!("  sign    --package <name> --version <ver> --integrity <hash>");
        eprintln!("  keygen");
        eprintln!("  health");
        process::exit(1);
    }

    let command = &args[1];

    match command.as_str() {
        "verify" => {
            let package   = get_flag(&args, "--package").unwrap_or_else(|| {
                eprintln!("colour-core verify: --package required");
                process::exit(1);
            });
            let version   = get_flag(&args, "--version").unwrap_or("latest");
            let integrity = get_flag(&args, "--integrity").unwrap_or("");
            cmd_verify(package, version, integrity);
        }

        "sign" => {
            let package   = get_flag(&args, "--package").unwrap_or_else(|| {
                eprintln!("colour-core sign: --package required");
                process::exit(1);
            });
            let version   = get_flag(&args, "--version").unwrap_or("latest");
            let integrity = get_flag(&args, "--integrity").unwrap_or("");
            cmd_sign(package, version, integrity);
        }

        "keygen" => {
            cmd_keygen();
        }

        "health" => {
            cmd_health();
        }

        unknown => {
            eprintln!("colour-core: unknown command '{}'", unknown);
            process::exit(1);
        }
    }
}
-e 
