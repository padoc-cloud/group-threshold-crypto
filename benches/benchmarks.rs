use criterion::{criterion_group, criterion_main, Criterion};
use group_threshold_cryptography::{Ciphertext, DecryptionShare, FastDecryptionShare, ThresholdEncryptionParameters, batch_share_combine, create_share, encrypt, fast_create_share, fast_share_combine, setup, share_combine};

pub fn bench_decryption(c: &mut Criterion) {
    use rand::SeedableRng;
    use rand_core::RngCore;

    const NUM_OF_TX: usize = 1000;

    #[derive(Debug, Clone)]
    pub struct TestingParameters {}

    impl ThresholdEncryptionParameters for TestingParameters {
        type E = ark_bls12_381::Bls12_381;
    }

    fn share_combine_bench(threshold: usize, num_of_msgs: usize) -> impl Fn() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let (pubkey, _, privkey_shares) = setup::<ark_std::rand::rngs::StdRng, TestingParameters>(
            &mut rng,
            threshold,
            num_of_msgs,
        );

        let mut messages: Vec<[u8; NUM_OF_TX]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            let mut msg: [u8; NUM_OF_TX] = [0u8; NUM_OF_TX];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(encrypt::<ark_std::rand::rngs::StdRng, TestingParameters>(
                &messages[j],
                pubkey,
                &mut rng,
            ));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..threshold {
                dec_shares[j].push(create_share(&ciphertexts[j], &privkey_shares[i]));
            }
        }

        let share_combine_prepared = move || {
            let c: Vec<Ciphertext<TestingParameters>> = ciphertexts.clone();
            let shares: Vec<Vec<DecryptionShare<TestingParameters>>> = dec_shares.clone();

            for i in 0..ciphertexts.len() {
                share_combine(&c[i], &shares[i]).unwrap();
            }
        };

        share_combine_prepared
    }

    fn batch_share_combine_bench(threshold: usize, num_of_msgs: usize) -> impl Fn() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let (pubkey, _, privkey_shares) = setup::<ark_std::rand::rngs::StdRng, TestingParameters>(
            &mut rng,
            threshold,
            num_of_msgs,
        );

        let mut messages: Vec<[u8; NUM_OF_TX]> = vec![];
        let mut ad: Vec<&[u8]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            ad.push("".as_bytes());
            let mut msg: [u8; NUM_OF_TX] = [0u8; NUM_OF_TX];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(encrypt(&messages[j], pubkey, &mut rng));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..threshold {
                dec_shares[j].push(create_share(&ciphertexts[j], &privkey_shares[i]));
            }
        }

        let batch_share_combine_prepared = move || {
            let c: Vec<Ciphertext<TestingParameters>> = ciphertexts.clone();
            let shares: Vec<Vec<DecryptionShare<TestingParameters>>> = dec_shares.clone();

            batch_share_combine(c, shares).unwrap();
        };

        batch_share_combine_prepared
    }

    fn fast_share_combine_bench(threshold: usize, num_of_msgs: usize) -> impl Fn() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);

        let (pubkey, _, privkey_shares) = setup::<ark_std::rand::rngs::StdRng, TestingParameters>(
            &mut rng,
            threshold,
            num_of_msgs,
        );

        let mut messages: Vec<[u8; NUM_OF_TX]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<FastDecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            let mut msg: [u8; NUM_OF_TX] = [0u8; NUM_OF_TX];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(encrypt::<ark_std::rand::rngs::StdRng, TestingParameters>(
                &messages[j],
                pubkey,
                &mut rng,
            ));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..threshold {
                dec_shares[j].push(fast_create_share(&ciphertexts[j], &privkey_shares[i], &mut rng));
            }
        }

        let share_combine_prepared = move || {
            let c: Vec<Ciphertext<TestingParameters>> = ciphertexts.clone();
            let shares: Vec<Vec<FastDecryptionShare<TestingParameters>>> = dec_shares.clone();

            for i in 0..ciphertexts.len() {
                fast_share_combine(&c[i], &shares[i]).unwrap();
            }
        };

        share_combine_prepared
    }

    let mut group = c.benchmark_group("TPKE");
    group.sample_size(10);

    // let a = share_combine_bench(08, 1000);
    // group.measurement_time(core::time::Duration::new(500, 0));
    // group.bench_function("share_combine_bench: threshold 08 - #msg 1000", |b| {
    //     b.iter(|| a())
    // });

    // let a = batch_share_combine_bench(08, 1000);
    // group.measurement_time(core::time::Duration::new(500, 0));
    // group.bench_function("batch_share_combine: threshold 08 - #msg 1000", |b| {
    //     b.iter(|| a())
    // });

    let a = fast_share_combine_bench(100, 1000);
    group.measurement_time(core::time::Duration::new(500, 0));
    group.bench_function("fast_share_combine: threshold 100 - #msg 1000", |b| {
        b.iter(|| a())
    });
}

criterion_group!(benches, bench_decryption);
criterion_main!(benches);
