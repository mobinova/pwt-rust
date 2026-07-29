# PWT — Protobuf Web Token (Rust)

**PWT** (Protobuf Web Token) stores JWT-style claims in Protocol Buffers.
It mirrors the Go implementation and uses the same signing algorithms.
Tokens are smaller than JSON JWTs, and parsing is faster thanks to protobuf
serialization. Custom data lives in a protobuf `Struct` payload.

---

## Why PWT?

- ✅ **Smaller tokens** via protobuf serialization
- 🚀 **Faster parse + verify** routines
- 🔒 Uses JWT-compatible signing algorithms (HS256, RS256, EdDSA)
- 🔁 Drop-in JWT-style workflow with typed claims

---

## Installation

```bash
cargo add pwt-rust
```

The library is imported as `pwt`:

```rust
use pwt::{Token, TokenBody};
```

PWT is currently in initial development. Releases in the `0.x` series may
include documented API changes before the public API is stabilized at `1.0.0`.

---

## Quick Start

```rust
use pwt::{Key, SigningMethodHS256, Token, TokenBody};
use prost_types::Struct;

let mut body = TokenBody::default();
body.iss = "example".to_string();
body.sub = "user-123".to_string();
body.exp = 1_700_000_000;

let mut payload = Struct::default();
payload.fields.insert(
    "role".to_string(),
    prost_types::Value {
        kind: Some(prost_types::value::Kind::StringValue("admin".to_string())),
    },
);
body.payload = Some(payload);

let token = Token::new_with_claims(SigningMethodHS256::new(), body);
let token_str = token.signed_string(&Key::from_bytes("secret"))?;

let parsed = Token::parse(&token_str, Some(&|_token| Ok(Key::from_bytes("secret"))))?;
println!("subject: {}", parsed.body.sub);
```

---

## Migrating from JWT

PWT maps directly to standard JWT claims:

| JWT Claim | PWT Field |
|-----------|-----------|
| `iss`     | `iss`     |
| `sub`     | `sub`     |
| `aud`     | `aud`     |
| `exp`     | `exp`     |
| `nbf`     | `nbf`     |
| `iat`     | `iat`     |
| `jti`     | `jti`     |

Custom claims should be stored in the protobuf `Struct` payload.

---

## API Notes

- `Token::new`, `Token::new_versioned`, and `Token::new_with_claims` mirror the
  Go API and create a token with a protobuf header/body.
- `Token::signed_string` encodes the header, body, and signature using base64url
  (no padding) in the same format as PWT-Go.
- `Token::parse` validates the signature and checks time-based claims.

---

## Tests

```bash
cargo test
```

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
development workflow and [SECURITY.md](SECURITY.md) for reporting security
issues.

---

## License

Licensed under the [MIT License](LICENSE).
