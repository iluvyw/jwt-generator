use std::io::stdin;

use base64::{prelude::BASE64_URL_SAFE, Engine};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;

const SECRET_KEY: &str = "secret";

fn encode<T: AsRef<[u8]>>(input: T) -> String {
    BASE64_URL_SAFE.encode(input).replace('=', "")
}

fn main() {
    let mut username = String::new();
    println!("Please enter your username:");
    stdin().read_line(&mut username).expect("Did not enter the correct string");
    let username = username.trim();

    let header = json!({
        "type": "JWT",
        "alg": "HS256"
    });
    let payload = json!({
        "username": username,
        "role": "dev"
    });

    let encoded_header = encode(&header.to_string());
    let encoded_payload = encode(&payload.to_string());
    let token_data = format!("{}.{}", encoded_header, encoded_payload);
    
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(SECRET_KEY.as_bytes()).expect("HMAC can take key of any size");
    mac.update(token_data.as_bytes());
    let result = mac.finalize();
    let signature: String = encode(result.into_bytes());
    let jwt = format!("{}.{}", token_data, &signature);
    
    println!("Here is your JWT:\n{}", &jwt);
}
