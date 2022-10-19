use ergo_lib::wallet::miner_fee::MINERS_FEE_ADDRESS;
use ergotree_ir::chain::ergo_box::{ErgoBoxCandidate, NonMandatoryRegisters};

use crate::constants::TX_FEE;

pub(crate) fn create_fee_candidate(creation_height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate {
        value: TX_FEE.try_into().unwrap(),
        ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
        tokens: None,
        additional_registers: NonMandatoryRegisters::empty(),
        creation_height,
    }
}
