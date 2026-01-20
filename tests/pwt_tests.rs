use prost_types::Struct;
use pwt::{
    Key, PwtError, SigningMethodEdDSA, SigningMethodHS256, SigningMethodRS256, Token, TokenBody,
    TokenValidationError,
};
use rand::rngs::OsRng;
use rand::RngCore;

fn make_body(exp_offset_secs: i64) -> TokenBody {
    let mut body = TokenBody::default();
    body.iss = "test".to_string();
    body.sub = "sub".to_string();
    body.exp = now() + exp_offset_secs;
    body.iat = now();

    let mut payload = Struct::default();
    payload.fields.insert(
        "role".to_string(),
        prost_types::Value {
            kind: Some(prost_types::value::Kind::StringValue("admin".to_string())),
        },
    );
    body.payload = Some(payload);

    body
}

#[test]
fn token_validation() {
    let mut body = make_body(-60);
    let err = body.valid().expect_err("expected expired error");
    assert_eq!(err, TokenValidationError::TokenExpired);

    body.exp = now() + 60;
    body.valid().expect("expected valid token");
}

#[test]
fn parse_fails_with_invalid_signature() {
    let token_str = create_test_token_hs256();
    let result = Token::parse(
        &token_str,
        Some(&|_token| Ok(Key::from_bytes("wrong_secret"))),
    );

    assert!(matches!(
        result,
        Err(PwtError::SignatureVerificationFailed(_))
    ));
}

#[test]
fn parse_fails_with_bad_token() {
    let bad_token = "!!..";
    let result = Token::parse(bad_token, Some(&|_token| Ok(Key::from_bytes("secret"))));
    assert!(matches!(
        result,
        Err(PwtError::Base64DecodingFailed("header"))
    ));
}

#[test]
fn parse_succeeds_with_ed25519() {
    let mut rng = OsRng;
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();

    let body = make_body(600);
    let token = Token::new_with_claims(SigningMethodEdDSA::new(), body);
    let token_str = token
        .signed_string(&Key::ed25519_private(signing_key))
        .expect("signed token");

    let parsed = Token::parse(
        &token_str,
        Some(&move |_token| Ok(Key::ed25519_public(verifying_key.clone()))),
    )
    .expect("parse token");

    assert_eq!(parsed.body.sub, "sub");
}

#[test]
fn parse_succeeds_with_rs256() {
    let mut rng = OsRng;
    let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa key");
    let public_key = rsa::RsaPublicKey::from(&private_key);

    let body = make_body(600);
    let token = Token::new_with_claims(SigningMethodRS256::new(), body);
    let token_str = token
        .signed_string(&Key::rsa_private(private_key))
        .expect("signed token");

    let parsed = Token::parse(
        &token_str,
        Some(&move |_token| Ok(Key::rsa_public(public_key.clone()))),
    )
    .expect("parse token");

    assert_eq!(parsed.body.iss, "test");
}

fn create_test_token_hs256() -> String {
    let body = make_body(600);
    let token = Token::new_with_claims(SigningMethodHS256::new(), body);
    token
        .signed_string(&Key::from_bytes("secret"))
        .expect("signed token")
}

fn now() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_secs() as i64
}
