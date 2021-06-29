use crate::hash_to_curve::htp_bls12381_g2;
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{Field, One, ToBytes, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_serialize::CanonicalSerialize;
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use rand_core::RngCore;
use std::usize;
use rayon::prelude::*;
use thiserror::Error;

mod hash_to_curve;

pub trait ThresholdEncryptionParameters {
    type E: PairingEngine;
}

type G1<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::G1Affine;
type G2<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::G2Affine;
type Fr<P: ThresholdEncryptionParameters> =
    <<P::E as PairingEngine>::G1Affine as AffineCurve>::ScalarField;

#[derive(Debug, Error)]
pub enum ThresholdEncryptionError {
    /// Error
    #[error("ciphertext verification failed")]
    CiphertextVerificationFailed,

    /// Error
    #[error("Decryption share verification failed")]
    DecryptionShareVerificationFailed,

    /// Hashing to curve failed
    #[error("Could not hash to curve")]
    HashToCurveError,

    #[error("plaintext verification failed")]
    PlaintextVerificationFailed,
}

#[derive(Clone, Debug)]
pub struct Ciphertext<P: ThresholdEncryptionParameters> {
    pub nonce: G1<P>,        // U
    pub ciphertext: Vec<u8>, // V
    pub auth_tag: G2<P>,     // W
}

#[derive(Clone, Debug)]
pub struct DecryptionShare<P: ThresholdEncryptionParameters> {
    pub decryptor_index: usize,
    pub decryption_share: <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk,
}

#[derive(Clone, Debug, Copy)]
pub struct PrivkeyShare<P: ThresholdEncryptionParameters> {
    pub index: usize,
    pub privkey: G2<P>,
    pub pubkey: G1<P>,
}

fn hash_to_g2<T: ark_serialize::CanonicalDeserialize>(message: &[u8]) -> T {
    let mut point_ser: Vec<u8> = Vec::new();
    let point = htp_bls12381_g2(message);
    point.serialize(&mut point_ser).unwrap();
    T::deserialize(&point_ser[..]).unwrap()
}

fn construct_tag_hash<P: ThresholdEncryptionParameters>(
    u: G1<P>,
    stream_ciphertext: &[u8],
) -> G2<P> {
    let mut hash_input = Vec::<u8>::new();
    u.write(&mut hash_input).unwrap();
    hash_input.extend_from_slice(stream_ciphertext);

    hash_to_g2(&hash_input)
}

pub fn setup<R: RngCore, P: ThresholdEncryptionParameters>(
    rng: &mut R,
    threshold: usize,
    shares_num: usize,
) -> (
    <<P as ThresholdEncryptionParameters>::E as PairingEngine>::G1Affine,
    <<P as ThresholdEncryptionParameters>::E as PairingEngine>::G2Affine,
    Vec<PrivkeyShare<P>>,
) {
    let g = G1::<P>::prime_subgroup_generator();
    let h = G2::<P>::prime_subgroup_generator();

    assert!(shares_num >= threshold);
    let threshold_poly = DensePolynomial::<Fr<P>>::rand(threshold - 1, rng);
    let mut pubkey_shares: Vec<G1<P>> = vec![];
    let mut privkey_shares = vec![];

    for i in 1..=shares_num {
        let pt = <Fr<P> as From<u64>>::from(i as u64);
        let privkey_coeff = threshold_poly.evaluate(&pt);

        pubkey_shares.push(g.mul(privkey_coeff).into());

        let privkey = PrivkeyShare::<P> {
            index: i,
            privkey: h.mul(privkey_coeff).into(),
            pubkey: pubkey_shares[i - 1],
        };
        privkey_shares.push(privkey);
    }

    let z = Fr::<P>::zero();
    let x = threshold_poly.evaluate(&z);
    let pubkey = g.mul(x);
    let privkey = h.mul(x);

    (pubkey.into(), privkey.into(), privkey_shares)
}

pub fn encrypt<R: RngCore, P: ThresholdEncryptionParameters>(
    message: &[u8],
    pubkey: <<P as ThresholdEncryptionParameters>::E as PairingEngine>::G1Affine,
    rng: &mut R,
) -> Ciphertext<P> {
    let r = Fr::<P>::rand(rng);
    let g = G1::<P>::prime_subgroup_generator();
    let h = G2::<P>::prime_subgroup_generator();

    let ry_prep = <P::E as PairingEngine>::G1Prepared::from(pubkey.mul(r).into());
    let s = P::E::product_of_pairings(&[(ry_prep, h.into())]);

    let u = g.mul(r).into();

    let mut prf_key = Vec::new();
    s.write(&mut prf_key).unwrap();
    let mut blake_params = blake2b_simd::Params::new();
    blake_params.hash_length(32);
    let mut hasher = blake_params.to_state();
    prf_key.write(&mut hasher).unwrap();
    let mut prf_key_32 = [0u8; 32];
    prf_key_32.clone_from_slice(hasher.finalize().as_bytes());

    let chacha_nonce = Nonce::from_slice(b"secret nonce");
    let mut cipher = ChaCha20::new(Key::from_slice(&prf_key_32), chacha_nonce);
    let mut v = message.to_vec();
    cipher.apply_keystream(&mut v);

    let w = construct_tag_hash::<P>(u, &v[..]).mul(r).into();

    Ciphertext::<P> {
        nonce: u,
        ciphertext: v,
        auth_tag: w,
    }
}

pub fn check_ciphertext_validity<P: ThresholdEncryptionParameters>(c: &Ciphertext<P>) -> bool {
    let g_inv = <P::E as PairingEngine>::G1Prepared::from(-G1::<P>::prime_subgroup_generator());
    let hash_g2 = <P::E as PairingEngine>::G2Prepared::from(construct_tag_hash::<P>(c.nonce, &c.ciphertext[..]));

    P::E::product_of_pairings(&[(<P::E as PairingEngine>::G1Prepared::from(c.nonce), hash_g2), (g_inv, <P::E as PairingEngine>::G2Prepared::from(c.auth_tag))]) == <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk::one()
}

pub fn decrypt<P: ThresholdEncryptionParameters>(
    ciphertext: Ciphertext<P>,
    privkey: <<P as ThresholdEncryptionParameters>::E as PairingEngine>::G2Affine,
) -> Vec<u8> {
    let s = P::E::product_of_pairings(&[(
        <P::E as PairingEngine>::G1Prepared::from(ciphertext.nonce),
        <P::E as PairingEngine>::G2Prepared::from(privkey),
    )]);

    let mut prf_key = Vec::new();
    s.write(&mut prf_key).unwrap();
    let mut blake_params = blake2b_simd::Params::new();
    blake_params.hash_length(32);
    let mut hasher = blake_params.to_state();
    prf_key.write(&mut hasher).unwrap();
    let mut prf_key_32 = [0u8; 32];
    prf_key_32.clone_from_slice(hasher.finalize().as_bytes());
    let chacha_nonce = Nonce::from_slice(b"secret nonce");
    let mut cipher = ChaCha20::new(Key::from_slice(&prf_key_32), chacha_nonce);
    let mut plaintext = ciphertext.ciphertext.to_vec();
    cipher.apply_keystream(&mut plaintext);

    plaintext
}

pub fn create_share<P: ThresholdEncryptionParameters>(
    ciphertext: &Ciphertext<P>,
    privkey_share: &PrivkeyShare<P>,
) -> DecryptionShare<P> {
    let decryption_share = P::E::product_of_pairings(&[(
        <P::E as PairingEngine>::G1Prepared::from(ciphertext.nonce),
        <P::E as PairingEngine>::G2Prepared::from(privkey_share.privkey),
    )]);

    DecryptionShare {
        decryptor_index: privkey_share.index,
        decryption_share,
    }
}

pub fn share_combine_no_check<P: ThresholdEncryptionParameters>(
    c: &Ciphertext<P>,
    shares: &Vec<DecryptionShare<P>>,
) -> Result<Vec<u8>, ThresholdEncryptionError> {


    let mut stream_cipher_key_curve_elem: <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk = <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk::one();

    for sh in shares.iter() {
        let mut lagrange_coeff: Fr<P> = Fr::<P>::one();
        let ji = <Fr<P> as From<u64>>::from(sh.decryptor_index as u64);
        for i in shares.iter() {
            let ii = <Fr<P> as From<u64>>::from(i.decryptor_index as u64);
            if ii != ji {
                lagrange_coeff *= (Fr::<P>::zero() - (ii)) / (ji - ii);
            }
        }
        stream_cipher_key_curve_elem *= sh.decryption_share.pow(lagrange_coeff.into());
    }

    let mut prf_key = Vec::new();
    stream_cipher_key_curve_elem.write(&mut prf_key).unwrap();
    let mut blake_params = blake2b_simd::Params::new();
    blake_params.hash_length(32);
    let mut hasher = blake_params.to_state();
    prf_key.write(&mut hasher).unwrap();
    let mut prf_key_32 = [0u8; 32];
    prf_key_32.clone_from_slice(hasher.finalize().as_bytes());

    let chacha_nonce = Nonce::from_slice(b"secret nonce");
    let mut cipher = ChaCha20::new(Key::from_slice(&prf_key_32), chacha_nonce);

    let mut plaintext = Vec::with_capacity(c.ciphertext.len());
    for _ in 0..c.ciphertext.len() {
        plaintext.push(Default::default());
    }

    plaintext.clone_from_slice(&c.ciphertext[..]);
    cipher.apply_keystream(&mut plaintext);

    Ok(plaintext)
}

pub fn share_combine<P: ThresholdEncryptionParameters>(
    c: &Ciphertext<P>,
    shares: &Vec<DecryptionShare<P>>,
) -> Result<Vec<u8>, ThresholdEncryptionError> {
    if !check_ciphertext_validity(&c) {
        return Err(ThresholdEncryptionError::CiphertextVerificationFailed);
    }

    share_combine_no_check::<P>(c, shares)
}

pub fn batch_share_combine<'a, P: 'static + ThresholdEncryptionParameters>(
    ciphertexts: Vec<Ciphertext<P>>,
    // additional_data: Vec<&[u8]>,
    shares: Vec<Vec<DecryptionShare<P>>>,
) -> Result<Vec<Vec<u8>>, ThresholdEncryptionError> {
    // We first check for ciphertext validity across ciphertexts: `e(-G, W_1) * e(U_1, H_1) * e(-G, W_2) * e(U_2, H_2) * ...`
    // We use an optimisation based on the billinearity property that implies: `\prod{e(-G, W_i)} = e(-G, \sum{W_i})`
    let g_inv = <P::E as PairingEngine>::G1Prepared::from(-G1::<P>::prime_subgroup_generator());
    let mut pairing_product: Vec<(
        <P::E as PairingEngine>::G1Prepared,
        <P::E as PairingEngine>::G2Prepared,
    )> = vec![];
    let mut auth_tag_sum: <P::E as PairingEngine>::G2Affine =
        <P::E as PairingEngine>::G2Affine::zero();

    ciphertexts
        .par_iter()
        .map(|c| {
            (
                c.nonce.into(),
                construct_tag_hash::<P>(c.nonce, &c.ciphertext[..]).into(),
            )
        })
        .collect_into_vec(&mut pairing_product);

    for c in ciphertexts.iter() {
        auth_tag_sum = auth_tag_sum + c.auth_tag;
    }
    pairing_product.push((g_inv, auth_tag_sum.into()));

    let pairing_prod_result = P::E::product_of_pairings(&pairing_product[..]);
    if pairing_prod_result != <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk::one()
    {
        return Err(ThresholdEncryptionError::CiphertextVerificationFailed);
    }

    // Decrypting each ciphertext
    let mut plaintexts: Vec<Vec<u8>> = Vec::with_capacity(ciphertexts.len());
    ciphertexts
        .par_iter()
        .zip(shares.par_iter())
        .map(|(c, sh)| share_combine_no_check(c, sh).unwrap().to_vec())
        .collect_into_vec(&mut plaintexts);

    Ok(plaintexts)
}


#[cfg(test)]
mod tests {
    use crate::*;
    use ark_std::test_rng;

    #[derive(Debug)]
    pub struct TestingParameters {}
    impl ThresholdEncryptionParameters for TestingParameters {
        type E = ark_bls12_381::Bls12_381;
    }

    #[test]
    fn symmetric_encryption() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 5;
        let msg: &[u8] = "abc".as_bytes();

        let (pubkey, privkey, _) = setup::<ark_std::rand::rngs::StdRng, TestingParameters>(
            &mut rng, threshold, shares_num,
        );

        let ciphertext =
            encrypt::<ark_std::rand::rngs::StdRng, TestingParameters>(msg, pubkey, &mut rng);
        let plaintext = decrypt(ciphertext, privkey);

        assert!(msg == plaintext)
    }

    #[test]
    fn threshold_encryption() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 5;
        let msg: &[u8] = "abc".as_bytes();

        let (pubkey, privkey, privkey_shares) = setup::<
            ark_std::rand::rngs::StdRng,
            TestingParameters,
        >(&mut rng, threshold, shares_num);
        let ciphertext =
            encrypt::<ark_std::rand::rngs::StdRng, TestingParameters>(msg, pubkey, &mut rng);

        let mut shares: Vec<DecryptionShare<TestingParameters>> = vec![];
        for privkey_share in privkey_shares {
            shares.push(create_share(&ciphertext, &privkey_share));
        }
        let plaintext = share_combine(&ciphertext, &shares).unwrap();

        assert!(plaintext == msg)
    }

    #[test]
    fn batch_share_combine_test() {
        let mut rng = test_rng();
        let threshold = 3;
        let shares_num = 5;
        let num_of_msgs = 4;

        let (pubkey, _, privkey_shares) = setup::<
            ark_std::rand::rngs::StdRng,
            TestingParameters,
        >(&mut rng, threshold, shares_num);

        let mut messages: Vec<[u8; 8]> = vec![];
        let mut ad: Vec<&[u8]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            ad.push("".as_bytes());
            let mut msg: [u8; 8] = [0u8; 8];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(encrypt(&messages[j], pubkey, &mut rng));

            dec_shares.push(Vec::with_capacity(shares_num));
            for privkey_share in &privkey_shares {
                dec_shares[j].push(create_share(&ciphertexts[j], privkey_share));
            }
        }

        let plaintexts = batch_share_combine(ciphertexts, dec_shares).unwrap();
        assert!(plaintexts.len() != 0);
        for (p, m) in plaintexts.into_iter().zip(messages) {
            assert!(*p == m)
        }
    }

}
