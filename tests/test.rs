use ark_ff::{to_bytes, UniformRand};
use barnett_smart_card_protocol::discrete_log_cards;
use barnett_smart_card_protocol::BarnettSmartProtocol;
use proof_essentials::utils::permutation::Permutation;
use proof_essentials::utils::rand::sample_vector;
use proof_essentials::zkp::proofs::{chaum_pedersen_dl_equality, schnorr_identification};
use thiserror_no_std::Error;
// Choose elliptic curve setting
type Curve = starknet_curve::Projective;
type Scalar = starknet_curve::Fr;
use ark_ff::One;
// Instantiate concrete type for our card protocol
type CardProtocol<'a> = discrete_log_cards::DLCards<'a, Curve>;
type CardParameters = discrete_log_cards::Parameters<Curve>;
type PublicKey = discrete_log_cards::PublicKey<Curve>;
type SecretKey = discrete_log_cards::PlayerSecretKey<Curve>;

type Card = discrete_log_cards::Card<Curve>;
type MaskedCard = discrete_log_cards::MaskedCard<Curve>;
type RevealToken = discrete_log_cards::RevealToken<Curve>;

type ProofKeyOwnership = schnorr_identification::proof::Proof<Curve>;
type RemaskingProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
type RevealProof = chaum_pedersen_dl_equality::proof::Proof<Curve>;
use rand::thread_rng;
use rand::Rng;
use std::collections::HashMap;

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

#[derive(Clone)]
struct Player {
    name: Vec<u8>,
    sk: SecretKey,
    pk: PublicKey,
    proof_key: ProofKeyOwnership,
    cards: Vec<MaskedCard>,
    opened_cards: Vec<Option<ClassicPlayingCard>>,
}

impl Player {
    pub fn new<R: Rng>(rng: &mut R, pp: &CardParameters, name: &Vec<u8>) -> anyhow::Result<Self> {
        let (pk, sk) = CardProtocol::player_keygen(rng, pp).unwrap();
        let proof_key = CardProtocol::prove_key_ownership(rng, pp, &pk, &sk, name).unwrap();
        Ok(Self {
            name: name.clone(),
            sk,
            pk,
            proof_key,
            cards: vec![],
            opened_cards: vec![],
        })
    }

    pub fn receive_card(&mut self, card: MaskedCard) {
        self.cards.push(card);
        self.opened_cards.push(None);
    }

    pub fn compute_reveal_token<R: Rng>(
        &self,
        rng: &mut R,
        pp: &CardParameters,
        card: &MaskedCard,
    ) -> anyhow::Result<(RevealToken, RevealProof, PublicKey)> {
        let (reveal_token, reveal_proof) =
            CardProtocol::compute_reveal_token(rng, &pp, &self.sk, &self.pk, card).unwrap();

        Ok((reveal_token, reveal_proof, self.pk))
    }

    pub fn peek_at_card(
        &mut self,
        parameters: &CardParameters,
        reveal_tokens: &mut Vec<(RevealToken, RevealProof, PublicKey)>,
        card_mappings: &HashMap<Card, ClassicPlayingCard>,
        card: &MaskedCard,
    ) -> Result<(), anyhow::Error> {
        let i = self.cards.iter().position(|&x| x == *card);

        let i = i.ok_or(GameErrors::CardNotFound).unwrap();

        //TODO add function to create that without the proof
        let rng = &mut thread_rng();
        let own_reveal_token = self.compute_reveal_token(rng, parameters, card).unwrap();
        reveal_tokens.push(own_reveal_token);

        let unmasked_card = CardProtocol::unmask(&parameters, reveal_tokens, card).unwrap();
        let opened_card = card_mappings.get(&unmasked_card);
        let opened_card = opened_card.ok_or(GameErrors::InvalidCard).unwrap();

        self.opened_cards[i] = Some(*opened_card);
        Ok(())
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

#[test]
fn run_game() -> anyhow::Result<()> {
    let m = 2;
    let n = 26;
    let num_of_cards = m * n;
    let rng = &mut thread_rng();

    let parameters = CardProtocol::setup(rng, m, n).unwrap();
    let card_mapping = encode_cards(rng, num_of_cards);

    let mut alice = Player::new(rng, &parameters, &to_bytes![b"Alice"].unwrap())?;
    let mut bob = Player::new(rng, &parameters, &to_bytes![b"Bob"].unwrap())?;

    let players = vec![alice.clone(), bob.clone()];

    let key_proof_info = players
        .iter()
        .map(|p| (p.pk, p.proof_key, p.name.clone()))
        .collect::<Vec<_>>();

    // Each player should run this computation.

    ///
    ///  Alternatively, it can be ran by a smart contract
    ///
    let joint_pk = CardProtocol::compute_aggregate_key(&parameters, &key_proof_info).unwrap();

    // Each player should run this computation and verify that all players agree on the initial deck
    let deck_and_proofs: Vec<(MaskedCard, RemaskingProof)> = card_mapping
        .keys()
        .map(|card| CardProtocol::mask(rng, &parameters, &joint_pk, &card, &Scalar::one()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let deck = deck_and_proofs
        .iter()
        .map(|x| x.0)
        .collect::<Vec<MaskedCard>>();

    // SHUFFLE TIME --------------
    // 1.a Alice shuffles first
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (a_shuffled_deck, a_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &deck,
        &masking_factors,
        &permutation,
    )
    .unwrap();

    // 1.b everyone checks!
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &deck,
        &a_shuffled_deck,
        &a_shuffle_proof,
    )
    .unwrap();

    //2.a Bob shuffles second
    let permutation = Permutation::new(rng, m * n);
    let masking_factors: Vec<Scalar> = sample_vector(rng, m * n);

    let (k_shuffled_deck, k_shuffle_proof) = CardProtocol::shuffle_and_remask(
        rng,
        &parameters,
        &joint_pk,
        &a_shuffled_deck,
        &masking_factors,
        &permutation,
    )
    .unwrap();

    //2.b Everyone checks
    CardProtocol::verify_shuffle(
        &parameters,
        &joint_pk,
        &a_shuffled_deck,
        &k_shuffled_deck,
        &k_shuffle_proof,
    )
    .unwrap();

    // CARDS ARE SHUFFLED. ROUND OF THE GAME CAN BEGIN
    let deck = k_shuffled_deck;

    alice.receive_card(deck[0]);
    bob.receive_card(deck[1]);

    let alice_rt_1 = alice.compute_reveal_token(rng, &parameters, &deck[1])?;

    let bob_rt_0 = bob.compute_reveal_token(rng, &parameters, &deck[0])?;

    let mut rts_alice = vec![bob_rt_0];
    let mut rts_bob = vec![alice_rt_1];

    //At this moment players privately open their cards and only they know that values
    alice
        .peek_at_card(&parameters, &mut rts_alice, &card_mapping, &deck[0])
        .unwrap();
    bob.peek_at_card(&parameters, &mut rts_bob, &card_mapping, &deck[1])
        .unwrap();

    Ok(())
}
