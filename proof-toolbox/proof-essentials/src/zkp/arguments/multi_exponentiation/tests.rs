#[cfg(test)]
mod test {

    use crate::error::CryptoError;
    use crate::homomorphic_encryption::{el_gamal, HomomorphicEncryptionScheme};
    use crate::utils::{
        rand::sample_vector,
        vector_arithmetic::{dot_product, reshape},
    };
    use crate::vector_commitment::{pedersen, HomomorphicCommitmentScheme};
    use crate::zkp::{arguments::multi_exponentiation, ArgumentOfKnowledge};

    use ark_ff::Zero;
    use ark_marlin::rng::FiatShamirRng;
    use ark_std::{rand::thread_rng, UniformRand};
    use blake2::Blake2s;
    use starknet_curve;
    use std::iter::Iterator;

    // Choose ellitptic curve setting
    type Curve = starknet_curve::Projective;
    type Scalar = starknet_curve::Fr;

    // Type aliases for concrete instances using the chosen EC.
    type Enc = el_gamal::ElGamal<Curve>;
    type Comm = pedersen::PedersenCommitment<Curve>;
    type Plaintext = el_gamal::Plaintext<Curve>;
    type Generator = el_gamal::Generator<Curve>;
    type Ciphertext = el_gamal::Ciphertext<Curve>;
    type Witness<'a> = multi_exponentiation::Witness<'a, Scalar>;
    type Statement<'a> = multi_exponentiation::Statement<'a, Scalar, Enc, Comm>;
    type MultiExpArg<'a> = multi_exponentiation::MultiExponentiation<'a, Scalar, Enc, Comm>;
    type FS = FiatShamirRng<Blake2s>;

    #[test]
    fn test_multi_exp() {
        let rng = &mut thread_rng();
        let m = 4;
        let n = 13;
        let number_of_ciphers = m * n;

        let encrypt_parameters = Enc::setup(rng).unwrap();
        let (pk, _) = Enc::keygen(&encrypt_parameters, rng).unwrap();

        let commit_key = Comm::setup(rng, n);

        let generator = Generator::rand(rng);

        let ciphers: Vec<Ciphertext> = sample_vector(rng, number_of_ciphers);
        let exponents: Vec<Scalar> = sample_vector(rng, number_of_ciphers);

        // construct parameters
        let parameters = multi_exponentiation::Parameters::new(
            &encrypt_parameters,
            &pk,
            &commit_key,
            &generator,
        );

        // Construct witness
        let a_chunks = reshape(&exponents, m, n).unwrap();

        let r: Vec<Scalar> = sample_vector(rng, m);

        let rho = Scalar::rand(rng);

        let witness = Witness::new(&a_chunks, &r, rho);

        // Construct statement
        let c_chunks = reshape(&ciphers, m, n).unwrap();

        let dot_prod = dot_product(&exponents, &ciphers).unwrap();
        let zero = Plaintext::zero();
        let masking_term = Enc::encrypt(&encrypt_parameters, &pk, &zero, &rho).unwrap();
        let grand_product = dot_prod + masking_term;

        let c_a = a_chunks
            .iter()
            .zip(r.iter())
            .map(|(a_chunk, random)| Comm::commit(&commit_key, a_chunk, *random).unwrap())
            .collect::<Vec<_>>();

        let statement = Statement::new(&c_chunks, grand_product, &c_a);

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        let proof =
            MultiExpArg::prove(rng, &parameters, &statement, &witness, &mut fs_rng).unwrap();

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        assert_eq!(
            (),
            proof.verify(&parameters, &statement, &mut fs_rng).unwrap()
        );

        let wrong_rho = Scalar::rand(rng);
        let wrong_witness = Witness::new(&a_chunks, &r, wrong_rho);

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        let invalid_proof =
            MultiExpArg::prove(rng, &parameters, &statement, &wrong_witness, &mut fs_rng).unwrap();

        let mut fs_rng = FS::from_seed(b"Initialised with some input");
        assert_eq!(
            invalid_proof.verify(&parameters, &statement, &mut fs_rng),
            Err(CryptoError::ProofVerificationError(String::from(
                "Multi Exponentiation",
            )))
        );
    }
}
