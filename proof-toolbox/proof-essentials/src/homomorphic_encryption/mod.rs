use crate::error::CryptoError;
use ark_ff::{Field, ToBytes, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::iter::Sum;
use ark_std::ops;
use ark_std::rand::Rng;

pub mod el_gamal;

/// Trait defining the types and functions needed for an additively homomorphic encryption scheme.
/// The scheme is defined with respect to a finite field `F` for which scalar multiplication is preserved.
pub trait HomomorphicEncryptionScheme<Scalar: Field> {
    type Parameters: CanonicalSerialize + CanonicalDeserialize;
    type PublicKey: CanonicalSerialize + CanonicalDeserialize + ToBytes;
    type SecretKey: CanonicalSerialize + CanonicalDeserialize;
    type Generator: Copy
        + ops::Add
        + ops::Mul<Scalar, Output = Self::Plaintext>
        + CanonicalSerialize
        + CanonicalDeserialize;

    /// Represent a plaintext from a generic homomorphic encryption scheme. To manifest the homomorphic
    /// property of the scheme, we require that some arithmetic operations (add and multiply by scalar) are implemented.
    type Plaintext: Copy
        + ops::Add
        + ops::Mul<Scalar, Output = Self::Plaintext>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Zero;

    /// Represent a ciphertext from a generic homomorphic encryption scheme. To manifest the homomorphic
    /// property of the scheme, we require that some arithmetic operations (add and multiply by scalar) are implemented.
    type Ciphertext: Copy
        + PartialEq
        + ops::Add<Output = Self::Ciphertext>
        + ops::Mul<Scalar, Output = Self::Ciphertext>
        + CanonicalSerialize
        + CanonicalDeserialize
        + Sum
        + Zero
        + ToBytes;

    /// Generate the scheme's parameters.
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, CryptoError>;

    /// Return a generator for the used group
    fn generator<R: Rng>(rng: &mut R) -> Result<Self::Generator, CryptoError>;

    /// Generate a public key and a private key.
    fn keygen<R: Rng>(
        pp: &Self::Parameters,
        rng: &mut R,
    ) -> Result<(Self::PublicKey, Self::SecretKey), CryptoError>;

    /// Encrypt a message using the provided public key and randomness.
    fn encrypt(
        pp: &Self::Parameters,
        pk: &Self::PublicKey,
        message: &Self::Plaintext,
        r: &Scalar,
    ) -> Result<Self::Ciphertext, CryptoError>;

    /// Recover a message from the provided ciphertext using a private key.
    fn decrypt(
        pp: &Self::Parameters,
        sk: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> Result<Self::Plaintext, CryptoError>;
}
