// Copyright © Aptos Foundation

use super::{field_check_input, field_parser::FieldParser};
use crate::input_processing::types::Input;
use anyhow::{anyhow, Result};
use aptos_crypto::poseidon_bn254;
use aptos_keyless_common::input_processing::config::CircuitConfig;
use aptos_types::keyless::{Configuration, IdCommitment};
use ark_bn254::Fr;

pub fn compute_idc_hash(
    input: &Input,
    config: &CircuitConfig,
    pepper_fr: Fr,
    jwt_payload: &str,
) -> Result<Fr> {
    let uid_field = FieldParser::find_and_parse_field(jwt_payload, &input.uid_key)?;

    let mut frs: Vec<Fr> = Vec::new();

    frs.push(pepper_fr);
    let aud_hash_fr = poseidon_bn254::pad_and_hash_string(
        &field_check_input::private_aud_value(input)?,
        *config
            .max_lengths
            .get("private_aud_value")
            .ok_or_else(|| anyhow!("Can't find key aud in config"))?,
    )?;
    frs.push(aud_hash_fr);
    let uid_val_hash_fr = poseidon_bn254::pad_and_hash_string(
        &uid_field.value,
        *config
            .max_lengths
            .get("uid_value")
            .ok_or_else(|| anyhow!("Can't find key uid in config"))?,
    )?;
    frs.push(uid_val_hash_fr);
    let uid_key_hash_fr = poseidon_bn254::pad_and_hash_string(
        &uid_field.key,
        *config
            .max_lengths
            .get("uid_name")
            .ok_or_else(|| anyhow!("Can't find key uid in config"))?,
    )?;
    frs.push(uid_key_hash_fr);

    poseidon_bn254::hash_scalars(frs)
}

pub const RSA_MODULUS_BYTES: usize = 256;

pub fn compute_temp_pubkey_frs(input: &Input) -> Result<([Fr; 3], Fr)> {
    let temp_pubkey_frs_with_len = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
        input.epk.to_bytes().as_slice(),
        Configuration::new_for_devnet().max_commited_epk_bytes as usize, // TODO should put this in my local config
    )?;

    Ok((
        temp_pubkey_frs_with_len[..3]
            .try_into()
            .expect("Length here should always be 3"),
        temp_pubkey_frs_with_len[3],
    ))
}

pub fn compute_public_inputs_hash(input: &Input, config: &CircuitConfig) -> anyhow::Result<Fr> {
    let pepper_fr = input.pepper_fr;
    let jwt_parts = &input.jwt_parts;
    let jwk = &input.jwk;
    let iss_field = FieldParser::find_and_parse_field(&jwt_parts.payload_decoded()?, "iss")?;
    let (temp_pubkey_frs, temp_pubkey_len) = compute_temp_pubkey_frs(input)?;

    let extra_field = field_check_input::parsed_extra_field_or_default(input)?;

    let override_aud_val_hashed = poseidon_bn254::pad_and_hash_string(
        &field_check_input::override_aud_value(input)?,
        IdCommitment::MAX_AUD_VAL_BYTES,
    )?;
    let use_override_aud = if let Some(_override_aud_val) = &input.idc_aud {
        ark_bn254::Fr::from(1)
    } else {
        ark_bn254::Fr::from(0)
    };

    // Add the epk as padded and packed scalars
    let mut frs = Vec::from(temp_pubkey_frs);

    frs.push(temp_pubkey_len);

    // Add the id_commitment as a scalar
    let addr_idc_fr = compute_idc_hash(input, config, pepper_fr, &jwt_parts.payload_decoded()?)?;
    frs.push(addr_idc_fr);

    // Add the exp_timestamp_secs as a scalar
    frs.push(Fr::from(input.exp_date_secs));

    // Add the epk lifespan as a scalar
    frs.push(Fr::from(input.exp_horizon_secs));

    let iss_val_hash = poseidon_bn254::pad_and_hash_string(
        &iss_field.value,
        *config
            .max_lengths
            .get("iss_value")
            .ok_or_else(|| anyhow!("Can't find key iss in config"))?,
    )?;
    frs.push(iss_val_hash);

    let use_extra_field_fr = Fr::from(input.use_extra_field() as u64);
    let extra_field_hash = poseidon_bn254::pad_and_hash_string(
        &extra_field.whole_field,
        *config
            .max_lengths
            .get("extra_field")
            .ok_or_else(|| anyhow!("Can't find key extra in config"))?,
    )?;
    frs.push(use_extra_field_fr);
    frs.push(extra_field_hash);

    // Add the hash of the jwt_header with the "." separator appended
    let jwt_header_str = jwt_parts.header_undecoded_with_dot();
    let jwt_header_hash = poseidon_bn254::pad_and_hash_string(
        &jwt_header_str,
        config.max_lengths["jwt_header_with_separator"],
    )?;
    frs.push(jwt_header_hash);

    let pubkey_hash_fr = jwk.to_poseidon_scalar()?;
    frs.push(pubkey_hash_fr);

    frs.push(override_aud_val_hashed);

    frs.push(use_override_aud);

    let result = poseidon_bn254::hash_scalars(frs)?;

    // debugging print statements which we used to check consistency with authenticator
    //     println!("Num EPK scalars:    {}", 4);
    //        for (i, e) in temp_pubkey_frs.iter().enumerate() {
    //            println!("EPK Fr[{}]:               {}", i, e.to_string())
    //        }
    //        println!("EPK Fr[{}]:                   {}", 4, temp_pubkey_len);
    //        println!("IDC:                          {}", addr_idc_fr);
    //        println!("exp_timestamp_secs:           {}", Fr::from(input.exp_date));
    //        println!("exp_horizon_secs:             {}", Fr::from(input.exp_horizon));
    //println!("iss val:              \'{}\'", &iss_field.value);
    //println!("iss val hash:               {}", iss_val_hash);
    //println!("max iss val length: {}", config.field_check_inputs.max_value_length("iss").unwrap());

    //    println!("addr_seed:              {}", &addr_idc_fr);
    //    println!("Extra field val:              {}", &extra_field.whole_field);
    //    println!("Use extra field:              {}", use_extra_field_fr);
    //    println!("Extra field hash:             {}", extra_field_hash);
    //    println!("JWT header val:               {}", jwt_header_str);
    //    println!("JWT header hash:              {}", jwt_header_hash);
    //    println!("JWK hash:                     {}", pubkey_hash_fr);
    //    println!("Override aud hash:            {}", override_aud_val_hashed);
    //    println!("Use override aud:             {}", use_override_aud);
    //    println!("result (public_inputs_hash):  {}", result.to_string());

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::compute_public_inputs_hash;
    use crate::input_processing::types::Input;
    use aptos_crypto::{
        ed25519::{Ed25519PrivateKey, Ed25519PublicKey},
        encoding_type::EncodingType,
        poseidon_bn254,
    };
    use aptos_keyless_common::input_processing::{
        config::CircuitConfig,
        encoding::{FromB64, JwtParts},
        sha::with_sha_padding_bytes,
    };
    use aptos_types::{
        jwks::rsa::RSA_JWK, keyless::Configuration, transaction::authenticator::EphemeralPublicKey,
    };
    use ark_bn254::Fr;
    use std::{fs, str::FromStr, sync::Arc};

    #[test]
    fn test_hashing() {
        let michael_pk_mod_str: &'static str =      "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw";
        let michael_pk_kid_str: &'static str = "test-rsa";
        let jwk = RSA_JWK::new_256_aqab(michael_pk_kid_str, michael_pk_mod_str);

        let jwt_b64 = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3RfandrIiwidHlwIjoiSldUIn0.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTM5OTAzMDcwODI4OTk3MTg3NzUiLCJoZCI6ImFwdG9zbGFicy5jb20iLCJlbWFpbCI6Im1pY2hhZWxAYXB0b3NsYWJzLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiYnhJRVN1STU5SW9aYjVhbENBU3FCZyIsIm5hbWUiOiJNaWNoYWVsIFN0cmFrYSIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vYS9BQ2c4b2NKdlk0a1ZVQlJ0THhlMUlxS1dMNWk3dEJESnpGcDlZdVdWWE16d1BwYnM9czk2LWMiLCJnaXZlbl9uYW1lIjoiTWljaGFlbCIsImZhbWlseV9uYW1lIjoiU3RyYWthIiwibG9jYWxlIjoiZW4iLCJpYXQiOjE3MDAyNTU5NDQsImV4cCI6MjcwMDI1OTU0NCwibm9uY2UiOiI5Mzc5OTY2MjUyMjQ4MzE1NTY1NTA5NzkwNjEzNDM5OTAyMDA1MTU4ODcxODE1NzA4ODczNjMyNDMxNjk4MTkzNDIxNzk1MDMzNDk4In0.Ejdu3RLnqe0qyS4qJrT7z58HwQISbHoqG1bNcM2JvQDF9h-SAm4X9R6oGfD_wSD8dvs9vaLbZCUhOB8pL-bmXXF25ZkDk1-PU1lWDnuZ77cYQKOrT259LdfPtscdn2DBClfQ5Faepzq-OdPZcfbNegpdclZyIn_jT_EJgO8BTRLP5QHpcPe5f9EsgP7ISw2UNIEB6mDn0hqVnB6MvAPmmYEY6VGgwqwKs1ntih8TEnL3bfJ3511MwhYJvnpAQ1l-c_htAGaVm98tC-rWD5QQKGAf1ONXG3_Rfq6JsTdBBq_p_3zxNUbD2WiEOSBRptZDNcGCbtI2SuPCY5o00NE6aQ";

        let ephemeral_private_key: Ed25519PrivateKey = EncodingType::Hex
            .decode_key(
                "zkid test ephemeral private key",
                "0x76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap();
        let ephemeral_public_key_unwrapped: Ed25519PublicKey =
            Ed25519PublicKey::from(&ephemeral_private_key);
        let epk = EphemeralPublicKey::ed25519(ephemeral_public_key_unwrapped);

        let input = Input {
            jwt_parts: JwtParts::from_b64(jwt_b64).unwrap(),
            jwk: Arc::new(jwk),
            epk,
            epk_blinder_fr: Fr::from_str("42").unwrap(),
            exp_date_secs: 1900255944,
            exp_horizon_secs: 100255944,
            pepper_fr: Fr::from_str("76").unwrap(),
            uid_key: String::from("sub"),
            extra_field: Some(String::from("family_name")),
            idc_aud: None,
            skip_aud_checks: false,
        };

        let jwt_parts = &input.jwt_parts;
        let _unsigned_jwt_no_padding = jwt_parts.unsigned_undecoded();
        //let jwt_parts: Vec<&str> = input.jwt_b64.split(".").collect();
        let _unsigned_jwt_with_padding =
            with_sha_padding_bytes(jwt_parts.unsigned_undecoded().as_bytes());
        let _signature = jwt_parts.signature().unwrap();
        let payload_decoded = jwt_parts.payload_decoded().unwrap();

        let _temp_pubkey_frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
            input.epk.to_bytes().as_slice(),
            Configuration::new_for_testing().max_commited_epk_bytes as usize, // TODO put my own thing here
        )
        .unwrap();

        let config: CircuitConfig = serde_yaml::from_str(
            &fs::read_to_string("conversion_config.yml").expect("Unable to read file"),
        )
        .expect("should parse correctly");

        println!("full jwt: {}", jwt_b64);
        println!(
            "decoded payload: {}",
            String::from_utf8(Vec::from(payload_decoded.as_bytes())).unwrap()
        );

        let hash = compute_public_inputs_hash(&input, &config).unwrap();

        assert_eq!(
            hash.to_string(),
            "18884813797014402005012488165063359209340898803829594097564044767682806702965"
        );
    }

    #[test]
    fn test_hashing_cognito_bad() {
        let michael_pk_mod_str: &'static str =      "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw";
        let michael_pk_kid_str: &'static str = "test-rsa";
        let jwk = RSA_JWK::new_256_aqab(michael_pk_kid_str, michael_pk_mod_str);

        let header = "eyJraWQiOiJaZlF5Y0xVcnQ5bnJhS05Cd1I1cnc5dEdcL1ZqWElyUFFUN3NXRFoxRGhoUT0iLCJhbGciOiJSUzI1NiJ9";
        let payload = "eyJjdXN0b206a2V5X2V4aXN0cyI6IjAiLCJhdF9oYXNoIjoiVHFlSFZWampQZ09oZnEyLXh6d2ROUSIsInN1YiI6IjIxNGQ1OGY1LTQyMmUtNDY0Ni1hOTE1LWQxNjc3NzBhMGY2YyIsImNvZ25pdG86Z3JvdXBzIjpbImFwLW5vcnRoZWFzdC0xX1FVWVRPQ21MTl9Hb29nbGUiXSwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAuYXAtbm9ydGhlYXN0LTEuYW1hem9uYXdzLmNvbVwvYXAtbm9ydGhlYXN0LTFfUVVZVE9DbUxOIiwiY29nbml0bzp1c2VybmFtZSI6Imdvb2dsZV8xMTE2Mjc3NzI0NjA3NTIzNDIzMTIiLCJub25jZSI6IjcwOTUyNDIzMzM5NjQ0NTcyNjc5MzQ3MjM3NjgwODAzMDMzMjQ0NjI4MjExOTE3NTY0MDk0NTAwOTk1MTk3ODEwNTE5MTAxODcxMTgiLCJvcmlnaW5fanRpIjoiZDEzNGFiZTAtN2RjMy00ZGZhLWE4ZGUtM2Y5YmM3MDJiMzI4IiwiYXVkIjoiMXAxMTB1MTRqbm5kNWU5OHFqNTVqa3ZuNmgiLCJpZGVudGl0aWVzIjpbeyJ1c2VySWQiOiIxMTE2Mjc3NzI0NjA3NTIzNDIzMTIiLCJwcm92aWRlck5hbWUiOiJHb29nbGUiLCJwcm92aWRlclR5cGUiOiJHb29nbGUiLCJpc3N1ZXIiOm51bGwsInByaW1hcnkiOiJ0cnVlIiwiZGF0ZUNyZWF0ZWQiOiIxNzMxNTc4NjgxMjk4In1dLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTczMTU3OTQ5OCwiY3VzdG9tOmV4cGlyYXRpb24iOiIxNzMxNTgyMjg5IiwiZXhwIjoxNzMxNTgzMDk4LCJpYXQiOjE3MzE1Nzk0OTgsImp0aSI6ImIxZjg5YjMyLWI1NDAtNGIyZS1iYjY0LWQ0YzlhZTYyMzQ4MiIsImVtYWlsIjoib2xpdmVyLmhlQGFwdG9zbGFicy5jb20ifQ";
        let jwt_b64 = format!("{}.{}.cFBuulZGYotZNxjCSmw_rCc-Zj7Sb8gCBmspNkvoCsk", header, payload);
        let ephemeral_private_key: Ed25519PrivateKey = EncodingType::Hex
            .decode_key(
                "zkid test ephemeral private key",
                "0x76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap();
        let ephemeral_public_key_unwrapped: Ed25519PublicKey =
            Ed25519PublicKey::from(&ephemeral_private_key);
        let epk = EphemeralPublicKey::ed25519(ephemeral_public_key_unwrapped);

        let input = Input {
            jwt_parts: JwtParts::from_b64(&jwt_b64).unwrap(),
            jwk: Arc::new(jwk),
            epk,
            epk_blinder_fr: Fr::from_str("42").unwrap(),
            exp_date_secs: 1900255944,
            exp_horizon_secs: 100255944,
            pepper_fr: Fr::from_str("76").unwrap(),
            uid_key: String::from("sub"),
            extra_field: None,
            idc_aud: None,
        };

        let jwt_parts = &input.jwt_parts;
        let _unsigned_jwt_no_padding = jwt_parts.unsigned_undecoded();
        //let jwt_parts: Vec<&str> = input.jwt_b64.split(".").collect();
        let _unsigned_jwt_with_padding = with_sha_padding_bytes(&jwt_parts.unsigned_undecoded());
        let _signature = jwt_parts.signature().unwrap();
        let payload_decoded = jwt_parts.payload_decoded().unwrap();

        let _temp_pubkey_frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
            input.epk.to_bytes().as_slice(),
            Configuration::new_for_testing().max_commited_epk_bytes as usize, // TODO put my own thing here
        )
        .unwrap();

        let config: CircuitConfig = serde_yaml::from_str(
            &fs::read_to_string("conversion_config.yml").expect("Unable to read file"),
        )
        .expect("should parse correctly");

        println!("full jwt: {}", jwt_b64);
        println!(
            "decoded payload: {}",
            String::from_utf8(Vec::from(payload_decoded.as_bytes())).unwrap()
        );

        let hash = compute_public_inputs_hash(&input, &config).unwrap();
    }

    #[test]
    fn test_hashing_cognito_good() {
        let michael_pk_mod_str: &'static str =      "6S7asUuzq5Q_3U9rbs-PkDVIdjgmtgWreG5qWPsC9xXZKiMV1AiV9LXyqQsAYpCqEDM3XbfmZqGb48yLhb_XqZaKgSYaC_h2DjM7lgrIQAp9902Rr8fUmLN2ivr5tnLxUUOnMOc2SQtr9dgzTONYW5Zu3PwyvAWk5D6ueIUhLtYzpcB-etoNdL3Ir2746KIy_VUsDwAM7dhrqSK8U2xFCGlau4ikOTtvzDownAMHMrfE7q1B6WZQDAQlBmxRQsyKln5DIsKv6xauNsHRgBAKctUxZG8M4QJIx3S6Aughd3RZC4Ca5Ae9fd8L8mlNYBCrQhOZ7dS0f4at4arlLcajtw";
        let michael_pk_kid_str: &'static str = "test-rsa";
        let jwk = RSA_JWK::new_256_aqab(michael_pk_kid_str, michael_pk_mod_str);

        let header = "eyJraWQiOiJaZlF5Y0xVcnQ5bnJhS05Cd1I1cnc5dEdcL1ZqWElyUFFUN3NXRFoxRGhoUT0iLCJhbGciOiJSUzI1NiJ9";
        let payload = "eyJjdXN0b206a2V5X2V4aXN0cyI6IjAiLCJhdF9oYXNoIjoiVHFlSFZWampQZ09oZnEyLXh6d2ROUSIsInN1YiI6IjIxNGQ1OGY1LTQyMmUtNDY0Ni1hOTE1LWQxNjc3NzBhMGY2YyIsImNvZ25pdG86Z3JvdXBzIjpbImFwLW5vcnRoZWFzdC0xX1FVWVRPQ21MTl9Hb29nbGUiXSwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJpc3MiOiJodHRwczovL2NvZ25pdG8taWRwLmFwLW5vcnRoZWFzdC0xLmFtYXpvbmF3cy5jb20vYXAtbm9ydGhlYXN0LTFfUVVZVE9DbUxOIiwiY29nbml0bzp1c2VybmFtZSI6Imdvb2dsZV8xMTE2Mjc3NzI0NjA3NTIzNDIzMTIiLCJub25jZSI6IjcwOTUyNDIzMzM5NjQ0NTcyNjc5MzQ3MjM3NjgwODAzMDMzMjQ0NjI4MjExOTE3NTY0MDk0NTAwOTk1MTk3ODEwNTE5MTAxODcxMTgiLCJvcmlnaW5fanRpIjoiZDEzNGFiZTAtN2RjMy00ZGZhLWE4ZGUtM2Y5YmM3MDJiMzI4IiwiYXVkIjoiMXAxMTB1MTRqbm5kNWU5OHFqNTVqa3ZuNmgiLCJpZGVudGl0aWVzIjpbeyJ1c2VySWQiOiIxMTE2Mjc3NzI0NjA3NTIzNDIzMTIiLCJwcm92aWRlck5hbWUiOiJHb29nbGUiLCJwcm92aWRlclR5cGUiOiJHb29nbGUiLCJpc3N1ZXIiOm51bGwsInByaW1hcnkiOiJ0cnVlIiwiZGF0ZUNyZWF0ZWQiOiIxNzMxNTc4NjgxMjk4In1dLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTczMTU3OTQ5OCwiY3VzdG9tOmV4cGlyYXRpb24iOiIxNzMxNTgyMjg5IiwiZXhwIjoxNzMxNTgzMDk4LCJpYXQiOjE3MzE1Nzk0OTgsImp0aSI6ImIxZjg5YjMyLWI1NDAtNGIyZS1iYjY0LWQ0YzlhZTYyMzQ4MiIsImVtYWlsIjoib2xpdmVyLmhlQGFwdG9zbGFicy5jb20ifQ";
        let jwt_b64 = format!("{}.{}.cFBuulZGYotZNxjCSmw_rCc-Zj7Sb8gCBmspNkvoCsk", header, payload);

        let ephemeral_private_key: Ed25519PrivateKey = EncodingType::Hex
            .decode_key(
                "zkid test ephemeral private key",
                "0x76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
                    .as_bytes()
                    .to_vec(),
            )
            .unwrap();
        let ephemeral_public_key_unwrapped: Ed25519PublicKey =
            Ed25519PublicKey::from(&ephemeral_private_key);
        let epk = EphemeralPublicKey::ed25519(ephemeral_public_key_unwrapped);

        let input = Input {
            jwt_parts: JwtParts::from_b64(&jwt_b64).unwrap(),
            jwk: Arc::new(jwk),
            epk,
            epk_blinder_fr: Fr::from_str("42").unwrap(),
            exp_date_secs: 1900255944,
            exp_horizon_secs: 100255944,
            pepper_fr: Fr::from_str("76").unwrap(),
            uid_key: String::from("sub"),
            extra_field: None,
            idc_aud: None,
        };

        let jwt_parts = &input.jwt_parts;
        let _unsigned_jwt_no_padding = jwt_parts.unsigned_undecoded();
        //let jwt_parts: Vec<&str> = input.jwt_b64.split(".").collect();
        let _unsigned_jwt_with_padding = with_sha_padding_bytes(&jwt_parts.unsigned_undecoded());
        let _signature = jwt_parts.signature().unwrap();
        let payload_decoded = jwt_parts.payload_decoded().unwrap();

        let _temp_pubkey_frs = poseidon_bn254::keyless::pad_and_pack_bytes_to_scalars_with_len(
            input.epk.to_bytes().as_slice(),
            Configuration::new_for_testing().max_commited_epk_bytes as usize, // TODO put my own thing here
        )
        .unwrap();

        let config: CircuitConfig = serde_yaml::from_str(
            &fs::read_to_string("conversion_config.yml").expect("Unable to read file"),
        )
        .expect("should parse correctly");

        println!("full jwt: {}", jwt_b64);
        println!(
            "decoded payload: {}",
            String::from_utf8(Vec::from(payload_decoded.as_bytes())).unwrap()
        );

        let hash = compute_public_inputs_hash(&input, &config).unwrap();
    }
}
