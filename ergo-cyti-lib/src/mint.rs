use std::collections::HashMap;

use crate::{
    constants::{MIN_BOX_VALUE, TX_FEE},
    tx::create_fee_candidate,
};
use bounded_vec::BoundedVecOutOfBounds;
use ergo_lib::{
    chain::transaction::unsigned::UnsignedTransaction,
    wallet::signing::{TransactionContext, TxSigningError},
};
use ergotree_ir::{
    chain::{
        address::Address,
        ergo_box::{
            box_value::BoxValueError, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId,
            NonMandatoryRegisters, NonMandatoryRegistersError,
        },
        token::{TokenAmount, TokenId},
    },
    mir::constant::{Constant, TryExtractInto},
    serialization::{SigmaParsingError, SigmaSerializationError},
};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CytiMintError {
    #[error("Box value error: {0}")]
    BoxValueError(#[from] BoxValueError),

    #[error("Register {0} is invalid or missing")]
    InvalidRegisterError(u8),

    #[error("Non mandatory register error: {0}")]
    NonMandatoryRegistersError(#[from] NonMandatoryRegistersError),

    #[error("Bounded vec error: {0}")]
    BoundedVecOutOfBounds(#[from] BoundedVecOutOfBounds),

    #[error("Sigma serialization error: {0}")]
    SigmaSerializationError(#[from] SigmaSerializationError),

    #[error("Sigma parsing error: {0}")]
    SigmaParsingError(#[from] SigmaParsingError),

    #[error("Tx signing error: {0}")]
    TxSigningError(#[from] TxSigningError),
}

pub fn create_token_mint_tx(
    solved_box: &ErgoBox,
    creation_height: u32,
) -> Result<TransactionContext<UnsignedTransaction>, CytiMintError> {
    let token_id: TokenId = solved_box.box_id().into();

    let mint_amount: TokenAmount = solved_box
        .additional_registers
        .get(NonMandatoryRegisterId::R4)
        .and_then(|c| c.clone().try_extract_into::<i64>().ok())
        .and_then(|amount| (amount as u64).try_into().ok())
        .ok_or_else(|| CytiMintError::InvalidRegisterError(4))?;

    let mint_info = solved_box
        .additional_registers
        .get(NonMandatoryRegisterId::R5)
        .and_then(|c| c.clone().try_extract_into::<Vec<Vec<u8>>>().ok())
        .ok_or_else(|| CytiMintError::InvalidRegisterError(5))?;

    let mint_address = solved_box
        .additional_registers
        .get(NonMandatoryRegisterId::R6)
        .and_then(|c| c.v.clone().try_into().ok())
        .map(Address::P2Pk)
        .ok_or_else(|| CytiMintError::InvalidRegisterError(6))?;

    let miner_address = solved_box
        .additional_registers
        .get(NonMandatoryRegisterId::R8)
        .and_then(|c| c.v.clone().try_into().ok())
        .map(Address::P2Pk)
        .ok_or_else(|| CytiMintError::InvalidRegisterError(8))?;

    let reward_candidate = ErgoBoxCandidate {
        value: (solved_box.value.as_i64() - TX_FEE as i64 - MIN_BOX_VALUE as i64).try_into()?,
        ergo_tree: miner_address.script()?,
        tokens: None,
        additional_registers: NonMandatoryRegisters::empty(),
        creation_height,
    };

    let mint_registers = HashMap::from([
        (
            NonMandatoryRegisterId::R4,
            Constant::from(mint_info[0].clone()),
        ),
        (
            NonMandatoryRegisterId::R5,
            Constant::from(mint_info[1].clone()),
        ),
        (
            NonMandatoryRegisterId::R6,
            Constant::from(mint_info[2].clone()),
        ),
        (
            NonMandatoryRegisterId::R7,
            Constant::from(mint_info[3].clone()),
        ),
        (
            NonMandatoryRegisterId::R8,
            Constant::from(mint_info[4].clone()),
        ),
        (
            NonMandatoryRegisterId::R9,
            Constant::from(mint_info[5].clone()),
        ),
    ]);

    let mint_candidate = ErgoBoxCandidate {
        value: (MIN_BOX_VALUE as i64).try_into()?,
        ergo_tree: mint_address.script()?,
        tokens: Some(vec![(token_id, mint_amount).into()].try_into()?),
        additional_registers: mint_registers.try_into()?,
        creation_height,
    };

    let miner_fee_candidate = create_fee_candidate(creation_height);

    let transaction = UnsignedTransaction::new(
        vec![solved_box.clone().into()].try_into()?,
        None,
        vec![reward_candidate, mint_candidate, miner_fee_candidate].try_into()?,
    )?;

    let transaction_context =
        TransactionContext::new(transaction, vec![solved_box.clone()], vec![])?;

    Ok(transaction_context)
}
