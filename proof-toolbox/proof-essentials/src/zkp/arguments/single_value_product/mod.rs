pub mod proof;
pub mod prover;
mod tests;

use crate::error::CryptoError;
use crate::vector_commitment::HomomorphicCommitmentScheme;
use crate::zkp::ArgumentOfKnowledge;
use ark_ff::Field;
use ark_marlin::rng::FiatShamirRng;
use ark_std::marker::PhantomData;
use ark_std::rand::Rng;
use ark_std::vec::Vec;
use digest::Digest;

pub struct SingleValueProductArgument<'a, F, Comm>
where
    F: Field,
    Comm: HomomorphicCommitmentScheme<F>,
{
    _field: PhantomData<&'a F>,
    _commitment_scheme: PhantomData<&'a Comm>,
}

impl<'a, Scalar, Comm> ArgumentOfKnowledge for SingleValueProductArgument<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    type CommonReferenceString = Parameters<'a, Scalar, Comm>;
    type Statement = Statement<'a, Scalar, Comm>;
    type Witness = Witness<'a, Scalar>;
    type Proof = proof::Proof<Scalar, Comm>;

    fn prove<R: Rng, D: Digest>(
        rng: &mut R,
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        witness: &Self::Witness,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<Self::Proof, CryptoError> {
        let prover = prover::Prover::new(common_reference_string, statement, witness);
        let proof = prover.prove(rng, fs_rng)?;

        Ok(proof)
    }

    fn verify<D: Digest>(
        common_reference_string: &Self::CommonReferenceString,
        statement: &Self::Statement,
        proof: &Self::Proof,
        fs_rng: &mut FiatShamirRng<D>,
    ) -> Result<(), CryptoError> {
        proof.verify(&common_reference_string, &statement, fs_rng)
    }
}

/// Parameters
pub struct Parameters<'a, F, Comm>
where
    F: Field,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub commit_key: &'a Comm::CommitKey,
    pub n: usize,
}

impl<'a, F, Comm> Parameters<'a, F, Comm>
where
    F: Field,
    Comm: HomomorphicCommitmentScheme<F>,
{
    pub fn new(n: usize, commit_key: &'a Comm::CommitKey) -> Self {
        Self { commit_key, n }
    }
}

/// Witness
pub struct Witness<'a, Scalar: Field> {
    pub a: &'a Vec<Scalar>,
    pub random_for_a_commit: &'a Scalar,
}

impl<'a, Scalar: Field> Witness<'a, Scalar> {
    pub fn new(a: &'a Vec<Scalar>, random_for_a_commit: &'a Scalar) -> Self {
        Self {
            a,
            random_for_a_commit,
        }
    }
}

/// Statement
pub struct Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub a_commit: &'a Comm::Commitment,
    pub b: Scalar,
}

impl<'a, Scalar, Comm> Statement<'a, Scalar, Comm>
where
    Scalar: Field,
    Comm: HomomorphicCommitmentScheme<Scalar>,
{
    pub fn new(a_commit: &'a Comm::Commitment, b: Scalar) -> Self {
        Self { a_commit, b }
    }
}
