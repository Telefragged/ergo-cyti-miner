use std::{
    collections::HashMap,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{constants::TX_FEE, tx::create_fee_candidate};
use bounded_vec::BoundedVecOutOfBounds;
use ergo_lib::{
    chain::transaction::{unsigned::UnsignedTransaction, UnsignedInput},
    ergo_chain_types::blake2b256_hash,
    wallet::signing::{TransactionContext, TxSigningError},
};
use ergotree_ir::{
    chain::{
        address::Address,
        ergo_box::{
            box_value::BoxValueError, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId,
            NonMandatoryRegistersError,
        },
    },
    mir::constant::{Constant, TryExtractInto},
    serialization::{SigmaSerializable, SigmaSerializationError},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CytiCalculateError {
    #[error("Box value error: {0}")]
    BoxValueError(#[from] BoxValueError),

    #[error("Non mandatory register error: {0}")]
    NonMandatoryRegistersError(#[from] NonMandatoryRegistersError),

    #[error("Address is not a P2Pk address")]
    NonP2PkAddress,

    #[error("Bounded vec error: {0}")]
    BoundedVecOutOfBounds(#[from] BoundedVecOutOfBounds),

    #[error("Sigma serialization error: {0}")]
    SigmaSerializationError(#[from] SigmaSerializationError),

    #[error("Tx signing error: {0}")]
    TxSigningError(#[from] TxSigningError),
}

fn find_pattern_idx(data: &[u8], pattern: &[u8]) -> usize {
    data.windows(pattern.len())
        .enumerate()
        .find(|(_, slice)| *slice == pattern)
        .map(|(idx, _)| idx)
        .unwrap()
}

fn write_to_idx(data: &mut [u8], src: &[u8], idx: usize) {
    data[idx..idx + src.len()].copy_from_slice(src)
}

pub fn try_calculate_tx(
    request_box: ErgoBox,
    creation_height: u32,
    miner_address: &Address,
) -> Result<Option<TransactionContext<UnsignedTransaction>>, CytiCalculateError> {
    let desired_box_id = request_box
        .additional_registers
        .get(NonMandatoryRegisterId::R7)
        .and_then(|c| c.clone().try_extract_into::<Vec<u8>>().ok())
        .unwrap();

    let mut registers: HashMap<_, Constant> = request_box.additional_registers.clone().into();

    let miner_dlog = if let Address::P2Pk(miner_pk) = miner_address {
        Ok(miner_pk.clone())
    } else {
        Err(CytiCalculateError::NonP2PkAddress)
    }?;

    let marker = 0x0123456789abcdef_u64.to_ne_bytes().to_vec();

    registers.insert(NonMandatoryRegisterId::R8, Constant::from(miner_dlog));

    // Insert known marker to find the position of the register value after serialization
    registers.insert(NonMandatoryRegisterId::R9, Constant::from(marker.clone()));

    let output_candidate = ErgoBoxCandidate {
        value: (request_box.value.as_i64() - TX_FEE as i64).try_into()?,
        ergo_tree: request_box.ergo_tree.clone(),
        tokens: None,
        additional_registers: registers.clone().try_into()?,
        creation_height,
    };

    let miner_fee_candidate = create_fee_candidate(creation_height);

    let request_input: UnsignedInput = request_box.clone().into();

    let tx = UnsignedTransaction::new(
        vec![request_input.clone()].try_into()?,
        None,
        vec![output_candidate.clone(), miner_fee_candidate.clone()].try_into()?,
    )?;

    let output_box = ErgoBox::from_box_candidate(&output_candidate, tx.id(), 0)?;

    let tx_id_bytes = tx.id().sigma_serialize_bytes()?;

    let mut tx_bytes = tx.bytes_to_sign()?;

    let mut output_bytes = output_box.sigma_serialize_bytes()?;

    let output_guess_slice_idx = find_pattern_idx(&output_bytes, &marker);
    let output_txid_slice_idx = find_pattern_idx(&output_bytes, &tx_id_bytes);
    let tx_guess_slice_idx = find_pattern_idx(&tx_bytes, &marker);

    let guesses = AtomicUsize::new(0);

    let solution = (0_u64..u64::MAX).into_iter().find(|guess| {
        guesses.fetch_add(1, Ordering::Relaxed);

        let guess_bytes = guess.to_ne_bytes();

        write_to_idx(&mut tx_bytes, &guess_bytes, tx_guess_slice_idx);

        let tx_id = blake2b256_hash(&tx_bytes);
        write_to_idx(&mut output_bytes, tx_id.0.as_slice(), output_txid_slice_idx);
        write_to_idx(&mut output_bytes, &guess_bytes, output_guess_slice_idx);

        let box_id = blake2b256_hash(&output_bytes);

        box_id.0[0..desired_box_id.len()] == desired_box_id
    });

    match solution {
        Some(guess) => {
            let guess_bytes = guess.to_ne_bytes().to_vec();
            registers.insert(
                NonMandatoryRegisterId::R9,
                Constant::from(guess_bytes.to_vec()),
            );
            let updated_candidate = ErgoBoxCandidate {
                additional_registers: registers.try_into()?,
                ..output_candidate
            };

            let transaction = UnsignedTransaction::new(
                vec![request_input].try_into()?,
                None,
                vec![updated_candidate, miner_fee_candidate].try_into()?,
            )?;

            let transaction_context =
                TransactionContext::new(transaction, vec![request_box], vec![])?;

            Ok(Some(transaction_context))
        }
        None => Ok(None),
    }
}
