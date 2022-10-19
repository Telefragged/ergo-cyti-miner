use wasm_bindgen::prelude::*;

use ergo_lib_wasm::{address::Address, ergo_box::ErgoBox, transaction::UnsignedTransaction};

#[wasm_bindgen]
pub struct CytiCalculation {
    calculated_tx: Option<UnsignedTransaction>,
    guesses: u64,
}

#[wasm_bindgen]
impl CytiCalculation {
    pub fn get_calculated_tx(&self) -> Option<UnsignedTransaction> {
        self.calculated_tx.clone()
    }
    pub fn get_guesses(&self) -> u64 {
        self.guesses
    }
}

#[wasm_bindgen]
pub fn try_calculate_tx(
    request_box: &ErgoBox,
    creation_height: u32,
    miner_address: &Address,
    search_from: u64,
    search_to: u64,
) -> CytiCalculation {
    let request_box = request_box.clone().into();
    let miner_address = miner_address.clone().into();

    let (result, guesses) = ergo_cyti_lib::calculate::try_calculate_tx(
        request_box,
        creation_height,
        &miner_address,
        Some(search_from),
        Some(search_to),
    )
    .unwrap();

    CytiCalculation {
        calculated_tx: result.map(|x| x.spending_tx).map(UnsignedTransaction::from),
        guesses,
    }
}
