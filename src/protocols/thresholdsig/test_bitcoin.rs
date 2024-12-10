#![allow(non_snake_case)]
/*
    Multisig Schnorr

    Copyright 2018 by Kzen Networks

    This file is part of Multisig Schnorr library
    (https://github.com/KZen-networks/multisig-schnorr)

    Multisig Schnorr is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multisig-schnorr/blob/master/LICENSE>
*/
use curv::elliptic::curves::traits::*;
use curv::arithmetic::traits::*;

use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::BigInt;

use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::secp256_k1::GE;
use protocols::thresholdsig::bitcoin_schnorr::*;


#[test]
#[allow(unused_doc_comments)]
fn test_t2_n4() {
    /// this test assumes that in keygen we have n=4 parties and in signing we have 4 parties as well.
    let t = 2;
    let n = 4;
    println!("parties:{:?}, threshold is {:?}", n, t);
    let key_gen_parties_index_vec: [usize; 4] = [0, 1, 2, 3];
    let key_gen_parties_points_vec = (0..key_gen_parties_index_vec.len())
        .map(|i| key_gen_parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();

    let (_priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
        keygen_t_n_parties(t.clone(), n.clone(), &key_gen_parties_points_vec);
    let parties_index_vec: [usize; 4] = [0, 1, 2, 3];
    let parties_points_vec = (0..parties_index_vec.len())
        .map(|i| parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();

    let (_eph_keys_vec, eph_shared_keys_vec, V, eph_vss_vec) =
        keygen_t_n_parties(t.clone(), n.clone(), &parties_points_vec);
    let message: [u8; 4] = [79, 77, 69, 82];
    println!("nullifier: {:?}", message);

    let local_sig_vec = (0..n.clone())
        .map(|i| LocalSig::compute(&message, &eph_shared_keys_vec[i], &priv_shared_keys_vec[i]))
        .collect::<Vec<LocalSig>>();
    let verify_local_sig = LocalSig::verify_local_sigs(
        &local_sig_vec,
        &parties_index_vec,
        &key_gen_vss_vec,
        &eph_vss_vec,
    );

    assert!(verify_local_sig.is_ok());
    let vss_sum_local_sigs = verify_local_sig.unwrap();
    let signature = Signature::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, V);
    //println!("signature: {:?}", signature);
    let verify_sig = signature.verify(&message, &Y);
    assert!(verify_sig.is_ok());
}

#[test]
#[allow(unused_doc_comments)]
fn test_t2_n5_sign_with_4() {
    // auditor
    let sk_a: FE = ECScalar::new_random();
    let y_a = &ECPoint::generator() * &sk_a;
    /// this test assumes that in keygen we have n=4 parties and in signing we have 4 parties, indices 0,1,3,4.
    let t = 2;
    let n = 5;
    /// keygen:
    let key_gen_parties_index_vec: [usize; 5] = [0, 1, 2, 3, 4];
    let key_gen_parties_points_vec = (0..key_gen_parties_index_vec.len())
        .map(|i| key_gen_parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();
    let (_priv_keys_vec, priv_shared_keys_vec, Y, key_gen_vss_vec) =
        keygen_t_n_parties(t.clone(), n.clone(), &key_gen_parties_points_vec);
    /// signing:
    let parties_index_vec: [usize; 4] = [0, 1, 3, 4];
    let parties_points_vec = (0..parties_index_vec.len())
        .map(|i| parties_index_vec[i].clone() + 1)
        .collect::<Vec<usize>>();
    let num_parties = parties_index_vec.len();
    let (_eph_keys_vec, eph_shared_keys_vec, V, eph_vss_vec) =
        keygen_t_n_parties(t.clone(), num_parties.clone(), &parties_points_vec);

    let message: [u8; 4] = [79, 77, 69, 82];
    let e_bn = HSha256::create_hash(&[&V.bytes_compressed_to_big_int(), &Y.bytes_compressed_to_big_int(), &BigInt::from_bytes(&message),]);
    let e: FE = ECScalar::from(&e_bn);
    // Encryption Key
    // Sigam = V + hash(m||V)*Y
    let Sigma =  Y * &e +V;
    let PK_enc = Sigma + y_a;
    println!("Auditor's PK_a: {:?}", y_a);
    println!("SIGMA is: {:?}", PK_enc);
    println!("Encryption PK_enc = PK_a + SIGMA: {:?}", PK_enc);
    // each party computes and share a local sig, we collected them here to a vector as each party should do AFTER receiving all local sigs
    let local_sig_vec = (0..num_parties.clone())
        .map(|i| {
            LocalSig::compute(
                &message,
                &eph_shared_keys_vec[i],
                &priv_shared_keys_vec[parties_index_vec[i]],
            )
        })
        .collect::<Vec<LocalSig>>();

    let verify_local_sig = LocalSig::verify_local_sigs(
        &local_sig_vec,
        &parties_index_vec,
        &key_gen_vss_vec,
        &eph_vss_vec,
    );
    let vss_sum_local_sigs = verify_local_sig.unwrap();

    /// each party / dealer can generate the signature
    let signature = Signature::generate(&vss_sum_local_sigs, &local_sig_vec, &parties_index_vec, V);
    let verify_sig = signature.verify(&message, &Y);
    // decryption keys
    let sk_dec = sk_a + signature.sigma;
    
    let PK_enc_1 = &ECPoint::generator()* &sk_a + &ECPoint::generator()* &signature.sigma;
    println!("PK_enc_1 = sk* G + s*G: {:?}", PK_enc_1);
    assert!(PK_enc_1 == PK_enc);
   
   // assert!(verify_sig.is_ok());
}

#[allow(dead_code)]
pub fn keygen_t_n_parties(
    t: usize,
    n: usize,
    parties: &[usize],
) -> (Vec<Keys>, Vec<SharedKeys>, GE, Vec<VerifiableSS<GE>>) {
    let parames = Parameters {
        threshold: t,
        share_count: n.clone(),
    };
    assert_eq!(parties.len(), n.clone());
    let party_keys_vec = (0..n.clone())
        .map(|i| Keys::phase1_create(parties[i]))
        .collect::<Vec<Keys>>();

    let mut bc1_vec = Vec::new();
    let mut blind_vec = Vec::new();
    for i in 0..n.clone() {
        let (bc1, blind) = party_keys_vec[i].phase1_broadcast();
        bc1_vec.push(bc1);
        blind_vec.push(blind);
    }

    let y_vec = (0..n.clone())
        .map(|i| party_keys_vec[i].y_i.clone())
        .collect::<Vec<GE>>();
    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);
    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();
    for i in 0..n.clone() {
        let (vss_scheme, secret_shares, index) = party_keys_vec[i]
            .phase1_verify_com_phase2_distribute(&parames, &blind_vec, &y_vec, &bc1_vec, parties)
            .expect("invalid key");
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares);
        index_vec.push(index);
    }

    let party_shares = (0..n.clone())
        .map(|i| {
            (0..n.clone())
                .map(|j| {
                    let vec_j = &secret_shares_vec[j];
                    vec_j[i].clone()
                })
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();

    let mut shared_keys_vec = Vec::new();
    for i in 0..n.clone() {
        let shared_keys = party_keys_vec[i]
            .phase2_verify_vss_construct_keypair(
                &parames,
                &y_vec,
                &party_shares[i],
                &vss_scheme_vec,
                &index_vec[i],
            )
            .expect("invalid vss");
        shared_keys_vec.push(shared_keys);
    }

    (party_keys_vec, shared_keys_vec, y_sum, vss_scheme_vec)
}
