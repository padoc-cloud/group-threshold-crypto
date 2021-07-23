use crate::*;
use ark_ec::ProjectiveCurve;

impl<E: PairingEngine> PrivateDecryptionContext<E> {
    pub fn prepare_combine(&self, shares: &[DecryptionShare<E>]) -> Vec<E::G2Prepared> {
        let mut domain = vec![];
        for D_i in shares.iter() {
            domain.extend(
                self.public_decryption_contexts[D_i.decryptor_index]
                    .domain
                    .iter(),
            );
        }
        let s = SubproductDomain::<E::Fr>::new(domain);
        let mut lagrange = s.inverse_lagrange_coefficients();
        ark_ff::batch_inversion(&mut lagrange);

        let mut start = 0usize;
        shares
            .iter()
            .map(|D_i| {
                let decryptor = &self.public_decryption_contexts[D_i.decryptor_index];
                let end = start + decryptor.domain.len();
                let lagrange_slice = &lagrange[start..end];
                start = end;
                E::G2Prepared::from(
                    izip!(
                        lagrange_slice.iter(),
                        decryptor.blinded_key_shares.window_tables.iter()
                    )
                    .map(|(lambda, base_table)| {
                        FixedBaseMSM::multi_scalar_mul::<E::G2Projective>(
                            self.scalar_bits,
                            self.window_size,
                            &base_table.window_table,
                            &[*lambda],
                        )[0]
                    })
                    .sum::<E::G2Projective>()
                    .into_affine(),
                )
            })
            .collect::<Vec<_>>()
    }
    pub fn share_combine(
        &self,
        ciphertext: &Ciphertext<E>,
        shares: &[DecryptionShare<E>],
        prepared_key_shares: &[E::G2Prepared],
    ) -> E::Fqk {
        let mut pairing_product: Vec<(E::G1Prepared, E::G2Prepared)> = vec![];

        for (D_i, blinded_key_share) in izip!(shares, prepared_key_shares.iter()) {
            pairing_product.push((
                E::G1Prepared::from(D_i.decryption_share),
                blinded_key_share.clone(),
            ));
        }
        E::product_of_pairings(&pairing_product)
    }
}
