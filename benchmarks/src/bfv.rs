use cupcake::{
    integer_arith::{scalar::Scalar, ArithUtils},
    traits::{
        AdditiveHomomorphicScheme, EncryptionOfZeros, KeyGeneration, SKEncryption, Serializable,
    },
    FVCiphertext,
};

use serde::de::{self, Deserialize, Deserializer, MapAccess, Visitor};
use serde::ser::{Serialize, SerializeStruct, Serializer};

use std::{error::Error, fmt};

use crate::ballot::Ballot;

pub type PublicKey = FVCiphertext<Scalar>;
pub type SecretKey = cupcake::SecretKey<Scalar>;

#[derive(Clone)]
pub struct BfvBallot {
    value: FVCiphertext<Scalar>,
    num_candidates: usize,
}

impl Ballot<PublicKey, SecretKey> for BfvBallot {
    fn generate_kepair() -> (PublicKey, SecretKey) {
        let scheme = cupcake::default();

        scheme.generate_keypair()
    }

    fn new(candidate: usize, num_candidates: usize, public_key: &PublicKey) -> Self {
        let scheme = cupcake::default();
        assert!(num_candidates < scheme.n);

        let mut value = scheme.encrypt_zero(public_key);
        value.1.coeffs[candidate] =
            Scalar::add_mod(&value.1.coeffs[candidate], &scheme.delta, &scheme.q);

        BfvBallot {
            value,
            num_candidates,
        }
    }

    fn decrypt(
        &self,
        secret_key: &SecretKey,
        _max: Option<usize>,
    ) -> Result<Vec<u64>, Box<dyn Error>> {
        let scheme = cupcake::default();

        let value: Vec<Scalar> = scheme.decrypt(&self.value, &secret_key);

        Ok(value.iter().map(Scalar::rep).collect())
    }
}

impl std::ops::Add<BfvBallot> for BfvBallot {
    type Output = BfvBallot;

    fn add(self, rhs: BfvBallot) -> Self::Output {
        let scheme = cupcake::default();
        let mut output = self.clone();

        scheme.add_inplace(&mut output.value, &rhs.value);

        output
    }
}

impl Serialize for BfvBallot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("BfvBallot", 2)?;

        // Serializar cada campo
        state.serialize_field("value", &self.value.to_bytes())?;
        state.serialize_field("num_candidates", &self.num_candidates)?;

        state.end()
    }
}

impl<'de> Deserialize<'de> for BfvBallot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        const FIELDS: &[&str] = &["value", "num_candidates"];

        struct BfvBallotVisitor;

        impl<'de> Visitor<'de> for BfvBallotVisitor {
            type Value = BfvBallot;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("un struct BfvBallot")
            }

            fn visit_map<V>(self, mut map: V) -> Result<BfvBallot, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut value = None;
                let mut num_candidates = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "value" => {
                            if value.is_some() {
                                return Err(de::Error::duplicate_field("value"));
                            }
                            let scheme = cupcake::default();
                            value = Some(scheme.from_bytes(&map.next_value()?));
                        }
                        "num_candidates" => {
                            if num_candidates.is_some() {
                                return Err(de::Error::duplicate_field("num_candidates"));
                            }
                            num_candidates = Some(map.next_value()?);
                        }
                        _ => return Err(de::Error::unknown_field(key, FIELDS)),
                    }
                }

                let value = value.ok_or_else(|| de::Error::missing_field("value"))?;
                let num_candidates =
                    num_candidates.ok_or_else(|| de::Error::missing_field("num_candidates"))?;

                Ok(BfvBallot {
                    value,
                    num_candidates,
                })
            }
        }

        // Llamar al Visitor
        deserializer.deserialize_struct("BfvBallot", FIELDS, BfvBallotVisitor)
    }
}

impl Into<Vec<u8>> for BfvBallot {
    fn into(self) -> Vec<u8> {
        bincode::serialize(&self).unwrap()
    }
}

impl From<Vec<u8>> for BfvBallot {
    fn from(raw: Vec<u8>) -> Self {
        bincode::deserialize(&raw).unwrap()
    }
}
