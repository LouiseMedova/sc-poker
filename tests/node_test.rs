use ark_ff::{to_bytes, UniformRand};
use barnett_smart_card_protocol::discrete_log_cards;
use barnett_smart_card_protocol::BarnettSmartProtocol;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use thiserror_no_std::Error;
use proof_essentials::homomorphic_encryption::el_gamal;
use ark_ec::AffineRepr;
use ark_ec::Group;

use ark_serialize::CanonicalDeserialize;
// Choose elliptic curve setting
type Curve = starknet_curve::Projective;
type Scalar = starknet_curve::Fr;
use ark_serialize::CanonicalSerialize;
use ark_ff::One;
// Instantiate concrete type for our card protocol
type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
type CardParameters = discrete_log_cards::Parameters<Curve>;
type PublicKey = discrete_log_cards::PublicKey<Curve>;
type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
type Card = discrete_log_cards::Card<Curve>;
type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
type RevealToken = discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
use rand::thread_rng;
use rand::Rng;
use std::collections::HashMap;

use sc_poker::{InitGame, GameAction};
use gclient::{EventListener, EventProcessor, GearApi, Result};
use gstd::{prelude::*};

#[derive(PartialEq, Clone, Copy, Eq)]
pub enum Suite {
    Club,
    Diamond,
    Heart,
    Spade,
}

impl Suite {
    const VALUES: [Self; 4] = [Self::Club, Self::Diamond, Self::Heart, Self::Spade];
}

#[derive(PartialEq, PartialOrd, Clone, Copy, Eq)]
pub enum Value {
    Two,
    Three,
    Four,
    Five,
    Six,
    Seven,
    Eight,
    Nine,
    Ten,
    Jack,
    Queen,
    King,
    Ace,
}


impl Value {
    const VALUES: [Self; 13] = [
        Self::Two,
        Self::Three,
        Self::Four,
        Self::Five,
        Self::Six,
        Self::Seven,
        Self::Eight,
        Self::Nine,
        Self::Ten,
        Self::Jack,
        Self::Queen,
        Self::King,
        Self::Ace,
    ];
}

#[derive(PartialEq, Clone, Eq, Copy)]
pub struct ClassicPlayingCard {
    value: Value,
    suite: Suite,
}

impl ClassicPlayingCard {
    pub fn new(value: Value, suite: Suite) -> Self {
        Self { value, suite }
    }
}


impl std::fmt::Debug for ClassicPlayingCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let suite = match self.suite {
            Suite::Club => "♣",
            Suite::Diamond => "♦",
            Suite::Heart => "♥",
            Suite::Spade => "♠",
        };

        let val = match self.value {
            Value::Two => "2",
            Value::Three => "3",
            Value::Four => "4",
            Value::Five => "5",
            Value::Six => "6",
            Value::Seven => "7",
            Value::Eight => "8",
            Value::Nine => "9",
            Value::Ten => "10",
            Value::Jack => "J",
            Value::Queen => "Q",
            Value::King => "K",
            Value::Ace => "A",
        };

        write!(f, "{}{}", val, suite)
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum GameErrors {
    #[error("No such card in hand")]
    CardNotFound,

    #[error("Invalid card")]
    InvalidCard,
}

fn encode_cards<R: Rng>(rng: &mut R, num_of_cards: usize) -> HashMap<Card, ClassicPlayingCard> {
    let mut map: HashMap<Card, ClassicPlayingCard> = HashMap::new();
    let plaintexts = (0..num_of_cards)
        .map(|_| Card::rand(rng))
        .collect::<Vec<_>>();

    let mut i = 0;
    for value in Value::VALUES.iter().copied() {
        for suite in Suite::VALUES.iter().copied() {
            let current_card = ClassicPlayingCard::new(value, suite);
            map.insert(plaintexts[i], current_card);
            i += 1;
        }
    }

    map
}

const PATH: &str = "./target/wasm32-unknown-unknown/release/sc_poker.opt.wasm";


async fn common_upload_program(
    client: &GearApi,
    code: Vec<u8>,
    payload: impl Encode,
) -> Result<([u8; 32], [u8; 32])> {
    let encoded_payload = payload.encode();
    // let gas_limit = client
    //     .calculate_upload_gas(None, code.clone(), encoded_payload, 0, true)
    //     .await?
    //     .min_limit;
    // println!("init gas {:?}", gas_limit );
    let (message_id, program_id, _) = client
        .upload_program(
            code,
            gclient::now_micros().to_le_bytes(),
            payload,
            250_000_000_000,
            0,
        )
        .await?;

    Ok((message_id.into(), program_id.into()))
}

async fn upload_program(
    client: &GearApi,
    listener: &mut EventListener,
    path: &str,
    payload: impl Encode,
) -> Result<[u8; 32]> {
    let (message_id, program_id) =
        common_upload_program(client, gclient::code_from_os(path)?, payload).await?;

    assert!(listener
        .message_processed(message_id.into())
        .await?
        .succeed());

    Ok(program_id)
}

#[tokio::test]
async fn node_run_game() -> Result<()> {

    let m = 2;
    let n = 26;
    let num_of_cards = m * n;
    let rng = &mut thread_rng();

    let parameters = CardProtocol::setup(rng, m, n).unwrap();
    let mut enc_bytes = Vec::new();
    let mut commit_bytes = Vec::new();
    let mut gen_bytes = Vec::new();

    let generator: G2 = G2::generator();

    generator.serialize_uncompressed(&mut enc_bytes).unwrap();

 //  parameters.enc_parameters.serialize_uncompressed(&mut enc_bytes).unwrap();
 //   let result = el_gamal::Parameters::<Curve>::deserialize_uncompressed(&*enc_bytes).unwrap();


 //   println!("{:?}",parameters.commit_parameters);
    // parameters.commit_parameters.serialize_uncompressed(&mut commit_bytes).unwrap();
    // println!("{:?}",commit_bytes);
    // parameters.generator.serialize_uncompressed(&mut gen_bytes).unwrap();

    let client = GearApi::dev().await?.with("//Alice")?;
    let mut listener = client.subscribe().await?;

    let program_id = upload_program(
        &client,
        &mut listener,
        PATH,
        InitGame {
            enc_parameters: enc_bytes,
            commit_parameters: commit_bytes,
            generator: gen_bytes,
        },
    )
    .await?;

    // let mut message_bytes = Vec::new();
    // message.serialize_compressed(&mut message_bytes).unwrap();

    // let payload = HandleMessage::MillerLoop {
    //     message: message_bytes,
    //     signatures,
    // };
    // let gas_limit = client
    //     .calculate_handle_gas(None, program_id.into(), payload.encode(), 0, true)
    //     .await?
    //     .min_limit;
    // println!("gas_limit {:?}", gas_limit);

    // let (message_id, _) = client
    //     .send_message(program_id.into(), payload, gas_limit, 0)
    //     .await?;

    // assert!(listener
    //     .message_processed(message_id.into())
    //     .await?
    //     .succeed());

    // let gas_limit = client
    //     .calculate_handle_gas(
    //         None,
    //         program_id.into(),
    //         HandleMessage::Exp.encode(),
    //         0,
    //         true,
    //     )
    //     .await?
    //     .min_limit;
    // println!("gas_limit {:?}", gas_limit);

    // let (message_id, _) = client
    //     .send_message(program_id.into(), HandleMessage::Exp, gas_limit, 0)
    //     .await?;

    // assert!(listener
    //     .message_processed(message_id.into())
    //     .await?
    //     .succeed());

    Ok(())
}
