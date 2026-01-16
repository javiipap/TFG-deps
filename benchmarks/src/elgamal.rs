use elastic_elgamal::{
    app::{ChoiceParams, EncryptedChoice},
    group::Ristretto,
    Ciphertext, DiscreteLogTable, Keypair,
};

use std::error::Error;

use crate::ballot::Ballot;

pub type PublicKey = elastic_elgamal::PublicKey<Ristretto>;
pub type SecretKey = elastic_elgamal::SecretKey<Ristretto>;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct ElGamalBallot {
    value: Vec<Ciphertext<Ristretto>>,
    num_candidates: usize,
}

impl Ballot<PublicKey, SecretKey> for ElGamalBallot {
    fn generate_kepair() -> (PublicKey, SecretKey) {
        let mut rng = rand::thread_rng();

        let keypair = Keypair::<Ristretto>::generate(&mut rng);

        (keypair.public().clone(), keypair.secret().clone())
    }

    fn new(candidate: usize, num_candidates: usize, public_key: &PublicKey) -> Self {
        let rng = &mut rand::thread_rng();
        let params = ChoiceParams::single(public_key.clone(), num_candidates);
        let value = EncryptedChoice::single(&params, candidate, rng);

        ElGamalBallot {
            value: value.choices_unchecked().into(),
            num_candidates,
        }
    }

    fn decrypt(
        &self,
        secret_key: &SecretKey,
        max: Option<usize>,
    ) -> Result<Vec<u64>, Box<dyn Error>> {
        let max_ = match max {
            Some(val) => val,
            None => 18014398492704769,
        };

        let lookup_table = DiscreteLogTable::new(0..=max_.try_into().unwrap());

        Ok(self
            .value
            .iter()
            .map(|choice| secret_key.decrypt(*choice, &lookup_table).unwrap())
            .collect())
    }
}

impl std::ops::Add<ElGamalBallot> for ElGamalBallot {
    type Output = ElGamalBallot;

    fn add(self, rhs: ElGamalBallot) -> Self::Output {
        let value = self
            .value
            .iter()
            .zip(rhs.value)
            .map(|(lhs, rhs)| lhs.add(rhs))
            .collect::<Vec<Ciphertext<Ristretto>>>();

        ElGamalBallot {
            value,
            num_candidates: self.num_candidates,
        }
    }
}

impl Into<Vec<u8>> for ElGamalBallot {
    fn into(self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl From<Vec<u8>> for ElGamalBallot {
    fn from(raw: Vec<u8>) -> Self {
        bincode::deserialize(&raw).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::Ballot;
    use super::ElGamalBallot;

    #[test]
    fn it_works() {
        let (public_key, secret_key) = ElGamalBallot::generate_kepair();
        let ballot_1 = ElGamalBallot::new(5, 10, &public_key);
        let ballot_2 = ElGamalBallot::new(6, 10, &public_key);
        let ballot_3 = ElGamalBallot::new(6, 10, &public_key);

        let result_1 = ballot_1 + ballot_2;

        let result_2 = result_1 + ballot_3;

        let output = result_2.decrypt(&secret_key, Some(18014398492704769));

        println!("{:?}", output);
    }
}
