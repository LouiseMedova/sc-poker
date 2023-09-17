pub mod pedersen;

use crate::error::CryptoError;
use ark_ff::{Field, ToBytes, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::iter::Sum;
use ark_std::rand::Rng;
use ark_std::vec::Vec;

/// Trait defining the types and functions needed for an additively homomorphic commitment scheme.
/// The scheme is defined with respect to a finite field `F` for which scalar multiplication is preserved.
pub trait HomomorphicCommitmentScheme<Scalar: Field> {
    type CommitKey: Clone + CanonicalSerialize + CanonicalDeserialize + ToBytes;

    /// Represent a ciphertext from a generic homomorphic encryption scheme. To manifest the homomorphic
    /// property of the scheme, we require that some arithmetic operations (add and multiply by scalar) are implemented.
    type Commitment: PartialEq
        + Copy
        + ark_std::ops::Add
        + ark_std::ops::Mul<Scalar, Output = Self::Commitment>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Zero
        + Sum
        + ToBytes;

    /// Generate a commit key using the provided length
    fn setup<R: Rng>(public_randomess: &mut R, len: usize) -> Self::CommitKey;

    /// Commit to a vector of scalars using the commit key
    fn commit(
        commit_key: &Self::CommitKey,
        x: &Vec<Scalar>,
        r: Scalar,
    ) -> Result<Self::Commitment, CryptoError>;
}
