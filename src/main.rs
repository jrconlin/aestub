use serde::{Deserialize, Serialize};
use std::env;
use std::process::exit;

// this matches what we're currently using for production.
#[derive(Debug, Serialize, Deserialize)]
struct VapidClaims {
    exp: u64,
    sub: String,
    aud: String,
}

// Try to decode the VAPID public key. (Note, this isn't the key that)
// is the public half of the VAPID private key, it's the public key used
// as part of the signature generation.
//
// For VAPID v1, this is the `p256ecdsa` sub key of the `Crypto-Key` header.
// For VAPID v2, this is the `k=` value in the `Authorization` header.
fn decode_public_key(public_key: &str) -> Result<Vec<u8>, String> {
    let encoding = if public_key.contains(['/', '+']) {
        base64::STANDARD_NO_PAD
    } else {
        base64::URL_SAFE_NO_PAD
    };
    base64::decode_config(public_key.trim_end_matches('='), encoding).map_err(|e| e.to_string())
}

// Try to help.
fn help() {
    println!("Usage: cargo run -- <vapid.token.string> <b64_publickey>")
}

// Parse and process the values.
// This mimicks the lead in for what subscription.rs does.
fn process(token: &str, key: &str) -> Result<(), String> {
    let public_key = decode_public_key(key)?;

    match jsonwebtoken::decode::<VapidClaims>(
        token,
        &jsonwebtoken::DecodingKey::from_ec_der(&public_key),
        &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256),
    ) {
        Ok(v) => {
            println!("Successfully decoded to {:?}", v.claims);
        }
        Err(e) => match e.kind() {
            jsonwebtoken::errors::ErrorKind::Json(e) => {
                println!("Is it a data error? {}", e.is_data());
                println!("{:?}", e.to_string());
                return Err(e.to_string());
            }
            _ => {
                println!("Not a JSON error: {:?}", e);
                return Err(e.to_string());
            }
        },
    }

    Ok(())
}

fn main() -> Result<(), String> {
    // absolutely the worst way to read in CLI args:
    let args: Vec<String> = env::args().collect();
    let token: &str = args.get(1).unwrap_or_else(|| {
        help();
        exit(-1);
    });
    let key: &str = args.get(2).unwrap_or_else(|| {
        help();
        exit(-1);
    });

    process(token, key)
}

#[cfg(test)]
mod tests {
    use super::process;

    #[test]
    fn test_process_ok() {
        // use a numeric exp
        /*
            {'sub': 'mailto:admin@example.com', 'aud': 'https://push.services.mozilla.com', 'exp': 1661022086}
        */
        assert!(process(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guc2VydmljZXMubW96aWxsYS5jb20iLCJleHAiOjE2NjEwMjIwODYsInN1YiI6Im1haWx0bzphZG1pbkBleGFtcGxlLmNvbSJ9.YhlRajSuF9SZ3avjDy3u6-XUl8M4HYjrhJEtMKFDMrTN1s-R_p6JgcQRMSuQ6EBpNZgbBtT5aA_WwNM3MlU6gg",
            "BLMymkOqvT6OZ1o9etCqV4jGPkvOXNz5FdBjsAR9zR5oeCV1x5CBKuSLTlHon-H_boHTzMtMoNHsAGDlDB6X7vI"
        ).is_ok());
    }

    #[test]
    fn test_process_str_exp() {
        // use a string exp
        /*
            {'sub': 'mailto:admin@example.com', 'aud': 'https://push.services.mozilla.com', 'exp': '1661021963'}
        */
        assert!(process(
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJhdWQiOiJodHRwczovL3B1c2guc2VydmljZXMubW96aWxsYS5jb20iLCJleHAiOiIxNjYxMDIxOTYzIiwic3ViIjoibWFpbHRvOmFkbWluQGV4YW1wbGUuY29tIn0.s8BxjZdxbCiCByFFgBEiGZA2sn_uydF0NWGL5NgyA6KthGXEm7Ng31QCol1PUPx96uq7r7w9_NfpeSd6I_4eGw",
            "BLMymkOqvT6OZ1o9etCqV4jGPkvOXNz5FdBjsAR9zR5oeCV1x5CBKuSLTlHon-H_boHTzMtMoNHsAGDlDB6X7vI"
        ).is_err())
    }
}
