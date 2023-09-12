use crate::discrete_log_cards::Card;
use crate::error::CardProtocolError;
use crate::Mask;

use ark_ec::ProjectiveCurve;
use proof_essentials::homomorphic_encryption::{
    el_gamal, el_gamal::ElGamal, HomomorphicEncryptionScheme,
};

impl<C: ProjectiveCurve> Mask<C::ScalarField, ElGamal<C>> for Card<C> {
    fn mask(
        &self,
        pp: &el_gamal::Parameters<C>,
        shared_key: &el_gamal::PublicKey<C>,
        r: &C::ScalarField,
    ) -> Result<el_gamal::Ciphertext<C>, CardProtocolError> {
        let ciphertext = ElGamal::<C>::encrypt(pp, shared_key, self, r)?;
        Ok(ciphertext)
    }
}
