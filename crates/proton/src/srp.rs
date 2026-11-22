//! Proton's SRP-6a variant (2048-bit, little-endian integers, bcrypt-hardened password hash).
//! Written from the algorithm in ProtonMail/go-srp (MIT); the same public parameters apply.
use base64::{Engine, engine::general_purpose::STANDARD};
use num_bigint::BigUint;
use sha2::{Digest, Sha512};

const BYTES: usize = 256;

fn from_le(bytes: &[u8]) -> BigUint {
	BigUint::from_bytes_le(bytes)
}

fn to_le(number: &BigUint) -> Vec<u8> {
	let mut bytes = number.to_bytes_le();
	bytes.resize(BYTES.max(bytes.len()), 0);
	bytes
}

/// 256 bytes: SHA-512 of `data` followed by the counters 0..=3.
pub fn expand_hash(data: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(256);
	for counter in 0..4u8 {
		let mut hash = Sha512::new();
		hash.update(data);
		hash.update([counter]);
		out.extend_from_slice(&hash.finalize());
	}
	out
}

/// The modulus arrives as a PGP clear-signed block whose body is base64.
/// shortcut: the PGP signature is not verified (it needs an OpenPGP stack). The transport is
/// TLS to Proton and `check_params` still rejects anything that is not a 2048-bit safe prime,
/// which is what the signature exists to guarantee; add verification if a PGP crate is vendored.
pub fn parse_modulus(signed: &str) -> Result<Vec<u8>, &'static str> {
	let body = signed
		.split("-----BEGIN PGP SIGNATURE-----")
		.next()
		.unwrap_or("");
	let mut lines = body.lines().map(str::trim);
	lines
		.by_ref()
		.find(|line| line.starts_with("-----BEGIN PGP SIGNED MESSAGE-----"))
		.ok_or("Malformed SRP modulus")?;
	// Armor headers (Hash: ...) end at the first blank line.
	lines.by_ref().find(|line| line.is_empty());
	let text: String = lines.filter(|line| !line.is_empty()).collect();
	let modulus = STANDARD.decode(text).map_err(|_| "Malformed SRP modulus")?;
	if modulus.len() == BYTES {
		Ok(modulus)
	} else {
		Err("SRP modulus has the wrong size")
	}
}

/// Account password hash for auth versions 3 and 4 (the only ones Proton still issues).
pub fn hash_password(
	version: i64,
	password: &[u8],
	salt: &[u8],
	modulus: &[u8],
) -> Result<Vec<u8>, &'static str> {
	if !(3..=4).contains(&version) {
		return Err("Unsupported Proton account auth version");
	}
	let mut salted = salt.to_vec();
	salted.extend_from_slice(b"proton");
	let salt: [u8; 16] = salted.try_into().map_err(|_| "Unexpected SRP salt size")?;
	let hashed = bcrypt::hash_with_salt(password, 10, salt)
		.map_err(|_| "Password hashing failed")?
		.format_for_version(bcrypt::Version::TwoY);
	let mut data = hashed.into_bytes();
	data.extend_from_slice(modulus);
	Ok(expand_hash(&data))
}

fn probably_prime(n: &BigUint) -> bool {
	let one = BigUint::from(1u8);
	let two = BigUint::from(2u8);
	if n < &two || (n % &two) == BigUint::ZERO {
		return n == &two;
	}
	let n_minus_1 = n - &one;
	let mut d = n_minus_1.clone();
	let mut r = 0u32;
	while (&d % &two) == BigUint::ZERO {
		d >>= 1;
		r += 1;
	}
	'bases: for base in [2u8, 3, 5, 7, 11, 13, 17, 19, 23, 29] {
		let a = BigUint::from(base);
		if a >= n_minus_1 {
			continue;
		}
		let mut x = a.modpow(&d, n);
		if x == one || x == n_minus_1 {
			continue;
		}
		for _ in 1..r {
			x = x.modpow(&two, n);
			if x == n_minus_1 {
				continue 'bases;
			}
		}
		return false;
	}
	true
}

/// What go-srp checks before trusting server-chosen parameters.
pub fn check_params(server_ephemeral: &BigUint, n: &BigUint) -> Result<(), &'static str> {
	let n_minus_1 = n - 1u8;
	if n.bits() != 2048 {
		return Err("SRP modulus has the wrong size");
	}
	// 3 mod 8, so that 2 generates the whole group.
	if !n.bit(0) || !n.bit(1) || n.bit(2) {
		return Err("SRP modulus is not 3 mod 8");
	}
	if server_ephemeral <= &BigUint::from(1u8) || server_ephemeral >= &n_minus_1 {
		return Err("SRP server ephemeral is out of bounds");
	}
	let half = n >> 1;
	if !probably_prime(&half) {
		return Err("SRP modulus is not a safe prime");
	}
	// 2^((N-1)/2) == -1 proves N prime given that (N-1)/2 is, and that 2 is not a square.
	if BigUint::from(2u8).modpow(&half, n) != n_minus_1 {
		return Err("SRP modulus is not prime");
	}
	Ok(())
}

pub struct Proofs {
	pub client_ephemeral: Vec<u8>,
	pub client_proof: Vec<u8>,
	pub expected_server_proof: Vec<u8>,
}

/// The client arithmetic, with the secret supplied (tests use a fixed one).
pub fn compute(
	hashed_password: &[u8],
	modulus: &[u8],
	server_ephemeral: &[u8],
	secret: &BigUint,
) -> Result<Proofs, &'static str> {
	if modulus.len() != BYTES || server_ephemeral.len() != BYTES {
		return Err("Unexpected SRP value size");
	}
	let n = from_le(modulus);
	let g = BigUint::from(2u8);
	let n_minus_1 = &n - 1u8;
	let k = from_le(&expand_hash(&[to_le(&g), to_le(&n)].concat())) % &n;
	if k <= BigUint::from(1u8) || k >= n_minus_1 {
		return Err("SRP multiplier is out of bounds");
	}
	let client_ephemeral = to_le(&g.modpow(secret, &n));
	let b = from_le(server_ephemeral);
	let u = from_le(&expand_hash(&[client_ephemeral.clone(), server_ephemeral.to_vec()].concat()));
	if u == BigUint::ZERO {
		return Err("SRP scrambling parameter is zero");
	}
	let x = from_le(hashed_password);
	let base = (&b + &n - (&k * g.modpow(&x, &n)) % &n) % &n;
	let exponent = (&u * &x + secret) % &n_minus_1;
	let shared = to_le(&base.modpow(&exponent, &n));
	let client_proof = expand_hash(&[client_ephemeral.clone(), server_ephemeral.to_vec(), shared.clone()].concat());
	let expected_server_proof =
		expand_hash(&[client_ephemeral.clone(), client_proof.clone(), shared].concat());
	Ok(Proofs {
		client_ephemeral,
		client_proof,
		expected_server_proof,
	})
}

/// Validates the server's parameters, draws the secret and computes the proofs.
pub fn generate(
	hashed_password: &[u8],
	modulus: &[u8],
	server_ephemeral: &[u8],
) -> Result<Proofs, &'static str> {
	let n = from_le(modulus);
	check_params(&from_le(server_ephemeral), &n)?;
	let n_minus_1 = &n - 1u8;
	loop {
		let mut random = [0u8; BYTES];
		getrandom::fill(&mut random).map_err(|_| "No system randomness")?;
		let secret = from_le(&random) % &n_minus_1;
		// Keep g^a above the modulus and a away from 0, as go-srp does.
		if secret > BigUint::from(4096u32) {
			return compute(hashed_password, modulus, server_ephemeral, &secret);
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// RFC 3526 group 14: a real 2048-bit safe prime. It is 7 mod 8, so `check_params` rightly
	/// refuses it; the client/server algebra does not care, so it still tests `compute`.
	const GROUP14: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";

	#[test]
	fn client_and_server_derive_the_same_secret_and_proofs() {
		let n = BigUint::parse_bytes(GROUP14.as_bytes(), 16).unwrap();
		let modulus = to_le(&n);
		let g = BigUint::from(2u8);
		let hashed = expand_hash(b"synthetic password hash");
		let x = from_le(&hashed);
		let verifier = g.modpow(&x, &n);
		// Server: B = k*v + g^b.
		let k = from_le(&expand_hash(&[to_le(&g), to_le(&n)].concat())) % &n;
		let b_secret = BigUint::from(0xDEAD_BEEF_u64) << 300;
		let big_b = (&k * &verifier + g.modpow(&b_secret, &n)) % &n;
		let server_ephemeral = to_le(&big_b);
		let a_secret = BigUint::from(0xC0FF_EE00_u64) << 400;
		let proofs = compute(&hashed, &modulus, &server_ephemeral, &a_secret).unwrap();
		// Server: S = (A * v^u)^b.
		let a = from_le(&proofs.client_ephemeral);
		let u = from_le(&expand_hash(&[proofs.client_ephemeral.clone(), server_ephemeral.clone()].concat()));
		let shared = to_le(&(&a * verifier.modpow(&u, &n) % &n).modpow(&b_secret, &n));
		let expected = expand_hash(&[proofs.client_ephemeral.clone(), server_ephemeral, shared.clone()].concat());
		assert_eq!(proofs.client_proof, expected, "client proof matches the server's view");
		let server_proof = expand_hash(&[proofs.client_ephemeral, proofs.client_proof, shared].concat());
		assert_eq!(proofs.expected_server_proof, server_proof);
	}

	#[test]
	fn hostile_srp_parameters_are_rejected() {
		let n = BigUint::parse_bytes(GROUP14.as_bytes(), 16).unwrap();
		let b = BigUint::from(12345u32);
		assert!(check_params(&b, &n).is_err(), "7 mod 8 modulus");
		let small = BigUint::from(1_000_003u32);
		assert!(check_params(&b, &small).is_err(), "wrong size");
		assert!(parse_modulus("not signed").is_err());
		assert!(hash_password(2, b"x", &[0; 10], &[0; 256]).is_err());
		assert!(probably_prime(&BigUint::from(1_000_003u32)));
		assert!(!probably_prime(&BigUint::from(1_000_001u32)));
	}

	#[test]
	fn clear_signed_modulus_body_is_extracted() {
		let body = STANDARD.encode([7u8; 256]);
		let signed = format!(
			"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{body}\n-----BEGIN PGP SIGNATURE-----\n\nxx\n-----END PGP SIGNATURE-----"
		);
		assert_eq!(parse_modulus(&signed).unwrap(), vec![7u8; 256]);
	}
}
