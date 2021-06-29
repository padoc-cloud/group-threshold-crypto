use criterion::{criterion_group, criterion_main, Criterion};
use group_threshold_cryptography::{
    create_share, encrypt,
    share_combine, setup, Ciphertext, DecryptionShare, ThresholdEncryptionParameters,
};

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
            &mut rng, threshold, num_of_msgs,
        );

        let mut messages: Vec<[u8; NUM_OF_TX]> = vec![];
        let mut ciphertexts: Vec<Ciphertext<TestingParameters>> = vec![];
        let mut dec_shares: Vec<Vec<DecryptionShare<TestingParameters>>> =
            Vec::with_capacity(ciphertexts.len());
        for j in 0..num_of_msgs {
            let mut msg: [u8; NUM_OF_TX] = [0u8; NUM_OF_TX];
            rng.fill_bytes(&mut msg);
            messages.push(msg.clone());

            ciphertexts.push(encrypt::<ark_std::rand::rngs::StdRng, TestingParameters>(&messages[j], pubkey, &mut rng));

            dec_shares.push(Vec::with_capacity(threshold));
            for i in 0..threshold {
                dec_shares[j].push(create_share(&ciphertexts[j], privkey_shares[i].clone()));
            }
        }

        let share_combine_prepared = move || {
            let c: Vec<Ciphertext<TestingParameters>> = ciphertexts.clone();
            let shares: Vec<Vec<DecryptionShare<TestingParameters>>> = dec_shares.clone();

            for i in 0..ciphertexts.len() {
                share_combine(c[i].clone(), shares[i].clone());
            }
        };

        share_combine_prepared
    }

    let mut group = c.benchmark_group("TPKE");
    group.sample_size(10);

    // // Benchmarking for larger number of messages
    let a = share_combine_bench(08, 1000);
    group.measurement_time(core::time::Duration::new(500, 0));
    group.bench_function("share_combine_bench: threshold 08 - #msg 1000", |b| {
        b.iter(|| a())
    });

}

criterion_group!(benches, bench_decryption);
criterion_main!(benches);
