use base64::prelude::*;
use elastic_elgamal::{
    app::{ChoiceParams, EncryptedChoice, SingleChoice},
    group::Ristretto,
    Ciphertext, PublicKey,
};
use serde_json;
use std::env;
use std::error::Error;

pub fn sum_ballot_option(ballot: &String, acc: &String) -> Result<(), Box<dyn Error>> {
    let parsed_ballot: EncryptedChoice<Ristretto, SingleChoice> = serde_json::from_str(&ballot)?;

    let mut parsed_acc: Vec<Ciphertext<Ristretto>> = match serde_json::from_str(&acc) {
        Ok(res) => res,
        Err(_) => vec![Ciphertext::<Ristretto>::zero(); parsed_ballot.choices_unchecked().len()],
    };

    assert_eq!(parsed_ballot.len(), parsed_acc.len());

    for (i, choice) in parsed_ballot.choices_unchecked().iter().enumerate() {
        parsed_acc[i] += *choice;
    }

    let parsed_result = serde_json::to_string(&parsed_acc)?;

    print!("{parsed_result}");

    Ok(())
}

pub fn verify_vote(
    pub_key_bytes: &Vec<u8>,
    vote: &String,
    options_count: usize,
) -> Result<(), Box<dyn Error>> {
    let receiver = PublicKey::<Ristretto>::from_bytes(&pub_key_bytes)?;
    let params = ChoiceParams::single(receiver, options_count);
    let ballot: EncryptedChoice<Ristretto, SingleChoice> = serde_json::from_str(&vote)?;

    ballot.verify(&params)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().collect::<Vec<String>>();

    eprintln!("{:?}", args);

    match args[1].as_str() {
        "--sum" => sum_ballot_option(&args[2], &args[3]),
        "--verify" => {
            let bytes = BASE64_STANDARD.decode(args[2].clone())?;

            verify_vote(&bytes, &args[3], args[4].parse::<usize>().unwrap())
        }
        _ => panic!("Unknown parameter"),
    }
}

#[test]
fn it_works() {
    let ballot_1 = "{\"choices\":[{\"random_element\":\"MtjvS8uAxr26JX2tcejQF9Z82P9g9ssiGDiaalQ8VD4\",\"blinded_element\":\"LJRdsCWFDMiffLCNyYgzCi4nc80IVXnAEUty6-ELqVU\"}],\"range_proof\":{\"common_challenge\":\"sb3oVaJ_g0hWYxki0_a9FcTQLsshHM460W5evsZoYwg\",\"ring_responses\":[\"waHwviZ_6ftD7pcGm701ypcxXa1gHbbr_od3vhCepQk\",\"NcXiMxcJW_H8anTnfg-ZBuL0jmZXZwmhBxYEvfAR3g0\"]},\"sum_proof\":{\"challenge\":\"8zrgUcqXo8eljr1jrHhIY8hIxPz4DEWiomnkMpv64g4\",\"response\":\"0Bz9ARV6jF0s_G-rW-akZsx8E3NtwZSk7lEzKsyItAU\"}}";
    sum_ballot_option(&ballot_1.to_string(), &"".to_string()).unwrap();
    let ballot_2 = "{\"choices\":[{\"random_element\":\"5Krhjl3mMacwl5_DosLiL47xj7HPavZ5q4rlOZv5skg\",\"blinded_element\":\"AL23UKH5shkOyJoxPSE7gPKeSDzPUVMJqkYdseCPiwk\"}],\"range_proof\":{\"common_challenge\":\"Lt2i969Tr3JjCBBEbIK1GrWYlsz1iOfQnOrUohigfgA\",\"ring_responses\":[\"iJvOATBLYfMectrSr_8yl50yl96sEZ8PSlpzjFJiXgc\",\"zgTpP59kX-6Pyd91D5L2XraYP0GtSPQjFTbyihhyOAo\"]},\"sum_proof\":{\"challenge\":\"1HgkCE5-uzVwjEoTIVXdktwmmrzTXQKDU-KO81craA4\",\"response\":\"oswjxE21JQIdtGu45JxOM9E6bZhe-dAHBZfDys8Tvwo\"}}";

    let res_1 = "[{\"random_element\":\"MtjvS8uAxr26JX2tcejQF9Z82P9g9ssiGDiaalQ8VD4\",\"blinded_element\":\"LJRdsCWFDMiffLCNyYgzCi4nc80IVXnAEUty6-ELqVU\"}]";
    sum_ballot_option(&ballot_2.to_string(), &res_1.to_string()).unwrap();
    let res_2 = "[{\"random_element\":\"gE0hppKFT0T8vSbsm4faGkXttWROUwS8fZeHGdX7tgQ\",\"blinded_element\":\"tvCZzqr-iNY0e3aV7IrWaFDTncuYfpqh4LPo_Vx62S4\"}]";
}
