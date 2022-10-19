use std::{
    collections::{HashMap, HashSet},
    sync::atomic::{AtomicUsize, Ordering},
};

use bounded_vec::BoundedVecOutOfBounds;
use ergo_lib::{
    chain::{
        ergo_state_context::ErgoStateContext,
        transaction::{unsigned::UnsignedTransaction, Transaction, UnsignedInput},
    },
    ergo_chain_types::{blake2b256_hash, Header, PreHeader},
    wallet::{
        miner_fee::MINERS_FEE_ADDRESS,
        signing::{TransactionContext, TxSigningError},
        Wallet,
    },
};
use ergotree_ir::{
    chain::{
        address::{Address, AddressEncoder, NetworkPrefix},
        ergo_box::{
            box_value::BoxValueError, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId,
            NonMandatoryRegisters, NonMandatoryRegistersError,
        },
        token::{TokenAmount, TokenId},
    },
    ergo_tree::ErgoTree,
    mir::constant::{Constant, TryExtractInto},
    serialization::{SigmaParsingError, SigmaSerializable, SigmaSerializationError},
};
use futures::future;
use log::{error, info};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;

const NODE_ADDRESS: &str = "http://172.19.208.1:9053";
const EXPLORER_ADDRESS: &str = "https://api.ergoplatform.com";
const MINER_ADDRESS: &str = "9i5vyrYekXGiXGrP3SA8Ukc4gaKm6xZHQ5B8Fi17BdR18qeput8";

const CYTI_CONTRACT_ERGOTREE: &str = "1020040004000404040005c0a3860105c0b5fa02010004060580897a05c0a38601040204020580897a04020402040204000402040004020400040204020402040404020406040204080402040a0100d80ad601e4c6a70608d602c5a7d603e4c6a7070ed604b17203d605b4720273007204d6069472057203d607b1a5d608b2a5730100d609e4c6a70405d60ae4c6a7051aeb02ea027201d17206d1ec95eded937207730293b4c572087303720472037206edededededededed93c27208c2a793c1720899c1a7730492c17208730593e4c672080405720993e4c67208051a720a93e4c672080608720193e4c67208070e7203e6c672080808e6c67208090e730695ed93720773079372057203edededededededededededed93c27208d0e4c6a7080892c172089999c1a77308730993c2b2a5730a00d0720193c1b2a5730b00730c93b1db6308b2a5730d00730e938cb2db6308b2a5730f00731000017202938cb2db6308b2a573110073120002720993e4c6b2a5731300040eb2720a73140093e4c6b2a5731500050eb2720a73160093e4c6b2a5731700060eb2720a73180093e4c6b2a5731900070eb2720a731a0093e4c6b2a5731b00080eb2720a731c0093e4c6b2a5731d00090eb2720a731e00731f";
const TX_FEE: u64 = 1100000;
const MIN_BOX_VALUE: u64 = 1000000;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UtxoResponse {
    items: Vec<ErgoBox>,
    total: u32,
}

async fn get_current_state_context(client: &Client) -> Result<ErgoStateContext, reqwest::Error> {
    let url = format!("{}/blocks/lastHeaders/{}", NODE_ADDRESS, 10);

    let mut last_headers = client
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<Header>>()
        .await?;

    last_headers.reverse();

    let pre_header: PreHeader = last_headers[0].clone().into();

    Ok(ErgoStateContext {
        headers: last_headers.try_into().unwrap(),
        pre_header,
    })
}

async fn get_utxos(client: &Client, ergo_tree: &str) -> Result<Vec<ErgoBox>, reqwest::Error> {
    let url = format!(
        "{}/api/v1/boxes/unspent/byErgoTree/{}",
        EXPLORER_ADDRESS, ergo_tree
    );
    let resp = client
        .get(url)
        .query(&[("limit", 200), ("offset", 0)])
        .send()
        .await?;
    let boxes = resp.json::<UtxoResponse>().await?.items;
    Ok(boxes)
}

async fn get_unconfirmed_boxes(
    client: &Client,
    ergo_tree: &ErgoTree,
) -> Result<Vec<ErgoBox>, reqwest::Error> {
    let url = format!("{}/transactions/unconfirmed", crate::NODE_ADDRESS);

    let transactions = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json::<Vec<Transaction>>()
        .await?;

    let spent = transactions
        .iter()
        .flat_map(|tx| tx.inputs.iter().map(|input| input.box_id.clone()))
        .collect::<HashSet<_>>();

    let unspent = transactions
        .into_iter()
        .flat_map(|tx| tx.outputs)
        .filter(|utxo| !spent.contains(&utxo.box_id()))
        .filter(|utxo| utxo.ergo_tree == *ergo_tree)
        .collect::<Vec<_>>();

    Ok(unspent)
}

fn deserialize_ergo_tree(tree: &str) -> ErgoTree {
    let bytes = base16::decode(tree.as_bytes()).unwrap();
    ErgoTree::sigma_parse_bytes(&bytes).unwrap()
}

fn check_request_unsolved(ergo_box: &ErgoBox) -> bool {
    let request_id = ergo_box
        .additional_registers
        .get(NonMandatoryRegisterId::R7)
        .and_then(|c| c.clone().try_extract_into::<Vec<i8>>().ok());

    match request_id {
        Some(request) => {
            let box_id_bytes: Vec<i8> = ergo_box.box_id().into();
            box_id_bytes[0..request.len()] != request
        }
        None => false,
    }
}

fn calculate_request_weight(ergo_box: &ErgoBox) -> u64 {
    let request_id = ergo_box
        .additional_registers
        .get(NonMandatoryRegisterId::R7)
        .and_then(|c| c.clone().try_extract_into::<Vec<i8>>().ok())
        .unwrap();

    let difficulty = 256_u64.pow(request_id.len() as u32);

    let value = *ergo_box.value.as_u64() * 1024;

    value / difficulty
}

#[derive(Error, Debug)]
enum CytiCalculateError {
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

fn create_fee_candidate(creation_height: u32) -> ErgoBoxCandidate {
    ErgoBoxCandidate {
        value: TX_FEE.try_into().unwrap(),
        ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
        tokens: None,
        additional_registers: NonMandatoryRegisters::empty(),
        creation_height,
    }
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

fn try_calculate(
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

    let tx_bytes = tx.bytes_to_sign()?;

    let output_bytes = output_box.sigma_serialize_bytes()?;

    let output_guess_slice_idx = find_pattern_idx(&output_bytes, &marker);
    let output_txid_slice_idx = find_pattern_idx(&output_bytes, &tx_id_bytes);
    let tx_guess_slice_idx = find_pattern_idx(&tx_bytes, &marker);

    let start_time = Instant::now();

    let guesses = AtomicUsize::new(0);

    let solution = (0_u64..u64::MAX).into_par_iter().find_any(|guess| {
        guesses.fetch_add(1, Ordering::Relaxed);

        let mut tx_bytes = tx_bytes.clone();

        let mut output_bytes = output_bytes.clone();

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
            let elapsed = Instant::now() - start_time;

            info!(
                "Solution found in {:.3}s, {:.1} guesses/s",
                elapsed.as_secs_f64(),
                guesses.load(Ordering::Relaxed) as f64 / elapsed.as_secs_f64()
            );
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

#[derive(Error, Debug)]
enum CytiMintError {
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

fn create_token_mint_tx(
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

#[derive(Serialize, Deserialize, Debug)]
struct ApiError {
    error: i32,
    reason: String,
    detail: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum ApiResponse<T> {
    Ok(T),
    Err(ApiError),
}

async fn send_transaction(
    client: &Client,
    transaction: &Transaction,
) -> Result<ApiResponse<String>, reqwest::Error> {
    let url = format!("{}/transactions", NODE_ADDRESS);

    client
        .post(&url)
        .json(transaction)
        .send()
        .await?
        .json::<ApiResponse<String>>()
        .await
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init_timed();

    let miner_address = AddressEncoder::new(NetworkPrefix::Mainnet)
        .parse_address_from_str(MINER_ADDRESS)
        .unwrap();

    let wallet = Wallet::from_mnemonic("", "").unwrap();

    let client = Client::builder().build().unwrap();

    let contract_tree = deserialize_ergo_tree(CYTI_CONTRACT_ERGOTREE);

    let (confirmed_boxes, mempool_boxes) = future::try_join(
        get_utxos(&client, CYTI_CONTRACT_ERGOTREE),
        get_unconfirmed_boxes(&client, &contract_tree),
    )
    .await
    .unwrap();

    let mut unsolved_requests = confirmed_boxes
        .into_iter()
        .chain(mempool_boxes.into_iter())
        .filter(check_request_unsolved)
        .collect::<Vec<_>>();

    unsolved_requests.sort_by_key(|eb| std::cmp::Reverse(calculate_request_weight(eb)));

    if let Some(request) = unsolved_requests.into_iter().next() {
        info!("New request: {:?}", request.box_id());
        let request_id = request
            .additional_registers
            .get(NonMandatoryRegisterId::R7)
            .and_then(|c| c.clone().try_extract_into::<Vec<u8>>().ok())
            .unwrap();

        let difficulty = 256_u64.pow(request_id.len() as u32);

        let request_hex: String = request_id
            .into_iter()
            .map(|c| format!("{:02x}", c))
            .collect();

        let request_value = *request.value.as_u64();

        info!(
            "Request: {}, value: {}, difficulty: {}, Weight: {}",
            request_hex,
            request_value,
            difficulty,
            calculate_request_weight(&request)
        );

        let state_context = get_current_state_context(&client).await.unwrap();

        let creation_height = state_context.headers[1].height;

        let result = try_calculate(request, creation_height, &miner_address).unwrap();

        if let Some(unsigned_tx) = result {
            let solved_tx = wallet
                .sign_transaction(unsigned_tx, &state_context, None)
                .unwrap();

            let solved_box = &solved_tx.outputs[0];

            let mint_unsigned = create_token_mint_tx(solved_box, creation_height).unwrap();

            let mint_tx = wallet
                .sign_transaction(mint_unsigned, &state_context, None)
                .unwrap();

            match send_transaction(&client, &solved_tx).await.unwrap() {
                ApiResponse::Ok(txid) => info!("Solving transaction with id {} submitted", txid),
                ApiResponse::Err(e) => {
                    error!("Failed to submit solving transaction: {:?}", e);
                    panic!();
                }
            }

            match send_transaction(&client, &mint_tx).await.unwrap() {
                ApiResponse::Ok(txid) => info!("Minting transaction with id {} submitted", txid),
                ApiResponse::Err(e) => {
                    error!("Failed to submit minting transaction: {:?}", e);
                    panic!();
                }
            }
        }
    } else {
        info!("No requests found")
    }
}
