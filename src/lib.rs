#![no_std]
use anyhow;

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_ff::Field;
use barnett_smart_card_protocol_for_sc::discrete_log_cards;
use barnett_smart_card_protocol_for_sc::BarnettSmartProtocol;
use gstd::{msg, prelude::*, debug, exec};
use proof_essentials::vector_commitment::pedersen::CommitKey;
//use ark_bls12_377::{ G1Affine, G1Projective as G1, G2Affine, G2Projective as G2};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;

use proof_essentials::homomorphic_encryption::el_gamal::ElGamal;

use proof_essentials::homomorphic_encryption::el_gamal;

use proof_essentials::vector_commitment::pedersen::PedersenCommitment;
use proof_essentials::zkp::arguments::shuffle;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
// Instantiate concrete type for our card protocol
type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;

type CardParameters = discrete_log_cards::Parameters<Curve>;

// Choose elliptic curve setting
type Curve = starknet_curve::Projective;
type Scalar = starknet_curve::Fr;
type Comm = PedersenCommitment<Curve>;

type Enc = ElGamal<Curve>;

type ZKProofShuffle = shuffle::proof::Proof<Scalar, Enc, Comm>;

type PublicKey = discrete_log_cards::PublicKey<Curve>;

type Card = discrete_log_cards::Card<Curve>;
type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
type RevealToken = discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;

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

#[derive(Clone)]
struct Player {
    name: String,
    pk: PublicKey,
    proof_key: ProofKeyOwnership,
    cards: Vec<MaskedCard>,
    opened_cards: Vec<Option<ClassicPlayingCard>>,
}

impl Player {
    pub fn new(pk: PublicKey, proof_key: ProofKeyOwnership, name: String) -> anyhow::Result<Self> {
        Ok(Self {
            name: name.clone(),
            pk,
            proof_key,
            cards: vec![],
            opened_cards: vec![],
        })
    }
}

pub struct Game {
    parameters: CardParameters,
    joint_pk: PublicKey,
    players: Vec<Player>,
    deck: Vec<MaskedCard>,
}

impl Game {
    fn add_player(&mut self, name: String, pk: Vec<u8>, proof_key: Vec<u8>) {
        // let pub_key: PublicKey = starknet_curve::Projective::deserialize_uncompressed(&*pk).unwrap().into();
        // let key_ownership =
        //     schnorr_identification::proof::Proof::<starknet_curve::Projective>::deserialize_uncompressed(&*proof_key)
        //         .unwrap();

        // let player = Player::new(pub_key, key_ownership, name).unwrap();
        // self.players.push(player);
    }

    fn shuffle(&mut self, deck: Vec<Vec<u8>>, shuffle_proof: Vec<u8>) {
        let mut shuffled_deck: Vec<MaskedCard> = Vec::new();
        for card in deck.iter() {
            let dec_card = MaskedCard::deserialize_uncompressed(&**card).unwrap();
            shuffled_deck.push(dec_card);
        }

        let dec_shuffle_proof = ZKProofShuffle::deserialize_uncompressed(&*shuffle_proof).unwrap();

        CardProtocol::verify_shuffle(
            &self.parameters,
            &self.joint_pk,
            &self.deck,
            &shuffled_deck,
            &dec_shuffle_proof,
        )
        .unwrap();

        self.deck = shuffled_deck;
    }
}

#[derive(Encode, Decode)]
pub struct InitGame {
    pub enc_parameters: Vec<u8>,
    pub commit_parameters: Vec<u8>,
    pub generator: Vec<u8>,
   
}

#[derive(Encode, Decode)]
pub enum GameAction {
    AddPlayer {
        name: String,
        pub_key: Vec<u8>,
        proof_key_ownership: Vec<u8>,
    },
    Shuffle {
        deck: Vec<Vec<u8>>,
        shuffle_proof: Vec<u8>,
    },
}
static mut GAME: Option<Game> = None;

#[no_mangle]
extern "C" fn handle() {
    let msg: GameAction = msg::load().expect("Unable to load the message");
    let game = unsafe { GAME.as_mut().expect("The contract is not initialized") };

    match msg {
        GameAction::AddPlayer {
            name,
            pub_key,
            proof_key_ownership,
        } => game.add_player(name, pub_key, proof_key_ownership),
        GameAction::Shuffle {
            deck,
            shuffle_proof,
        } => game.shuffle(deck, shuffle_proof),
    }
}

#[no_mangle]
extern "C" fn init() {
    let init_msg: InitGame = msg::load().expect("Unable to load the init msg");

    debug!("GAS {:?}", exec::gas_available());
    // let enc_parameters = G1::deserialize_uncompressed_unchecked(&*init_msg.enc_parameters)
    //     .unwrap();
    let enc_parameters = G1::deserialize_uncompressed(&*init_msg.enc_parameters)
        .unwrap();
    debug!("GAS {:?}", exec::gas_available());

    let enc_parameters = G1::deserialize_uncompressed(&*init_msg.enc_parameters)
    .unwrap();
    debug!("GAS {:?}", exec::gas_available());

    let enc_parameters = G1::deserialize_uncompressed(&*init_msg.enc_parameters)
        .unwrap();

        debug!("GAS {:?}", exec::gas_available());
   // debug!("HERE {:?}", exec::gas_available());
    let enc_parameters = el_gamal::Parameters::<starknet_curve::Projective>::deserialize_uncompressed(&*init_msg.enc_parameters)
        .unwrap();

      debug!("HERE {:?}", exec::gas_available());


    // let commit_parameters = CommitKey::<starknet_curve::Projective>::deserialize_uncompressed(&*init_msg.commit_parameters)
    //     .unwrap();

//   //      debug!("HERE {:?}", exec::gas_available());
//     let generator = el_gamal::Generator::<G1>::deserialize_uncompressed(&*init_msg.generator)
//         .unwrap()
//         .into();
//     let parameters =
//         discrete_log_cards::Parameters::new(2, 26, enc_parameters, commit_parameters, generator);

//   //      debug!("HERE");
//     let game = Game {
//         parameters,
//         joint_pk: PublicKey::default(),
//         players: Vec::new(),
//         deck: Vec::new(),
//     };
//     unsafe { GAME = Some(game) };
}
