use base64::{prelude::BASE64_URL_SAFE, Engine};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

const SECRET_KEY: &str = "secret";

fn main() {
    let header = json!({
        "type": "JWT",
        "alg": "HS256"
    });
    let payload = json!({
        "username": "anpham",
        "role": "dev"
    });

    let encoded_header = BASE64_URL_SAFE.encode(&header.to_string()).replace('=', "");
    let encoded_payload = BASE64_URL_SAFE.encode(&payload.to_string()).replace('=', "");
    let token_data = format!("{}.{}", encoded_header, encoded_payload);
    
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(SECRET_KEY.as_bytes()).expect("HMAC can take key of any size");
    mac.update(token_data.as_bytes());
    let result = mac.finalize();
    let signature: String = BASE64_URL_SAFE.encode(result.into_bytes()).replace('=', "");
    let jwt = format!("{}.{}", token_data, &signature);
    
    println!("Your token is {}", &jwt);
}
