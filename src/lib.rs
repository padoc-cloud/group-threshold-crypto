use crate::hash_to_curve::htp_bls12381_g2;
use ark_ec::{AffineCurve, PairingEngine};
use ark_ff::{One, ToBytes, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use ark_serialize::CanonicalSerialize;
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};
use chacha20::{ChaCha20, Key, Nonce};
use rand_core::RngCore;
use std::usize;

mod hash_to_curve;

pub trait ThresholdEncryptionParameters {
    type E: PairingEngine;
}

type G1<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::G1Affine;
type G2<P: ThresholdEncryptionParameters> = <P::E as PairingEngine>::G2Affine;
type Fr<P: ThresholdEncryptionParameters> =
    <<P::E as PairingEngine>::G1Affine as AffineCurve>::ScalarField;


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

#[derive(Clone, Debug)]
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

fn setup<R: RngCore, P: ThresholdEncryptionParameters>(
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

    let a = Fr::<P>::rand(rng);
    let pubkey = g.mul(a);
    let privkey = h.mul(a);

    // TODO: generate shares

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
    (pubkey.into(), privkey.into(), privkey_shares)
}

fn encrypt<R: RngCore, P: ThresholdEncryptionParameters>(
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

    print!("s = {:?}", s);

    let mut prf_key = Vec::new();
    s.write(&mut prf_key).unwrap();
    let mut blake_params = blake2b_simd::Params::new();
    blake_params.hash_length(32);
    let mut hasher = blake_params.to_state();
    prf_key.write(&mut hasher).unwrap();
    let mut prf_key_32 = [0u8; 32];
    prf_key_32.clone_from_slice(hasher.finalize().as_bytes());

    println!("prf_key_32 = {:?}", prf_key_32);

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

fn check_ciphertext_validity<P: ThresholdEncryptionParameters>(c: Ciphertext<P>) -> bool {
    let g_inv = -G1::<P>::prime_subgroup_generator();
    // TODO: P::E::product_of_pairings(&[]) == ;
    true
}

fn decrypt<P: ThresholdEncryptionParameters>(
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

fn create_share<P: ThresholdEncryptionParameters>(
    ciphertext: &Ciphertext<P>,
    privkey_share: PrivkeyShare<P>,
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

fn share_combine<P: ThresholdEncryptionParameters>(
    c: Ciphertext<P>,
    shares: Vec<DecryptionShare<P>>,
) -> Vec<u8> {
    let mut stream_cipher_key_curve_elem: <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk = <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk::zero();
    for sh in shares.iter() {
        let mut lagrange_coeff: <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk =
            <<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk::one();
        let ji =
            <<<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk as From<u64>>::from(
                sh.decryptor_index as u64,
            );
        for i in shares.iter() {
            let ii = <<<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk as From<
                u64,
            >>::from(i.decryptor_index as u64);
            if ii != ji {
                lagrange_coeff *=
                    (<<P as ThresholdEncryptionParameters>::E as PairingEngine>::Fqk::zero()
                        - (ii))
                        / (ji - ii);
            }
        }
        stream_cipher_key_curve_elem =
            stream_cipher_key_curve_elem + sh.decryption_share * lagrange_coeff;
    }

    // TODO: we don't get the expected result after lagrange interpolation
    print!("stream_cipher_key_curve_elem = {:?}", stream_cipher_key_curve_elem);

    let mut prf_key = Vec::new();
    stream_cipher_key_curve_elem.write(&mut prf_key).unwrap();
    let mut blake_params = blake2b_simd::Params::new();
    blake_params.hash_length(32);
    let mut hasher = blake_params.to_state();
    prf_key.write(&mut hasher).unwrap();
    let mut prf_key_32 = [0u8; 32];
    prf_key_32.clone_from_slice(hasher.finalize().as_bytes());

    println!("prf_key_32 = {:?}", prf_key_32);

    let chacha_nonce = Nonce::from_slice(b"secret nonce");
    let mut cipher = ChaCha20::new(Key::from_slice(&prf_key_32), chacha_nonce);

    let mut plaintext = Vec::with_capacity(c.ciphertext.len());
    for _ in 0..c.ciphertext.len() {
        plaintext.push(Default::default());
    }

    plaintext.clone_from_slice(&c.ciphertext[..]);
    cipher.apply_keystream(&mut plaintext);

    plaintext
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

        let (pubkey, privkey, privkey_shares) = setup::<ark_std::rand::rngs::StdRng, TestingParameters>(
            &mut rng, threshold, shares_num,
        );
        let ciphertext =
            encrypt::<ark_std::rand::rngs::StdRng, TestingParameters>(msg, pubkey, &mut rng);

        let mut shares: Vec<DecryptionShare<TestingParameters>> = vec![];
        for privkey_share in privkey_shares {
            shares.push(create_share(&ciphertext, privkey_share));
        }
        let plaintext = share_combine(ciphertext, shares);

        print!("plaintext = {:?}", plaintext);
        assert!(plaintext == msg)
    }
}
