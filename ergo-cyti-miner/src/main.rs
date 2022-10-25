use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{channel, Receiver, SendError, Sender},
    },
    thread::spawn,
};

use ergo_lib::{
    chain::{ergo_state_context::ErgoStateContext, transaction::Transaction},
    ergo_chain_types::{Header, PreHeader},
    wallet::Wallet,
};
use ergotree_ir::{
    chain::{
        address::{AddressEncoder, NetworkPrefix},
        ergo_box::{ErgoBox, NonMandatoryRegisterId},
    },
    ergo_tree::ErgoTree,
    mir::constant::TryExtractInto,
    serialization::SigmaSerializable,
};

use ergo_cyti_lib::{calculate::CytiCalculateRequest, mint::create_token_mint_tx};

use futures::future;
use log::{error, info};
use rayon::prelude::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use reqwest::Client;
use serde::{Deserialize, Serialize};

const NODE_ADDRESS: &str = "http://172.19.208.1:9053";
const EXPLORER_ADDRESS: &str = "https://api.ergoplatform.com";
const MINER_ADDRESS: &str = "9i5vyrYekXGiXGrP3SA8Ukc4gaKm6xZHQ5B8Fi17BdR18qeput8";

const CYTI_CONTRACT_ERGOTREE: &str = "1020040004000404040005c0a3860105c0b5fa02010004060580897a05c0a38601040204020580897a04020402040204000402040004020400040204020402040404020406040204080402040a0100d80ad601e4c6a70608d602c5a7d603e4c6a7070ed604b17203d605b4720273007204d6069472057203d607b1a5d608b2a5730100d609e4c6a70405d60ae4c6a7051aeb02ea027201d17206d1ec95eded937207730293b4c572087303720472037206edededededededed93c27208c2a793c1720899c1a7730492c17208730593e4c672080405720993e4c67208051a720a93e4c672080608720193e4c67208070e7203e6c672080808e6c67208090e730695ed93720773079372057203edededededededededededed93c27208d0e4c6a7080892c172089999c1a77308730993c2b2a5730a00d0720193c1b2a5730b00730c93b1db6308b2a5730d00730e938cb2db6308b2a5730f00731000017202938cb2db6308b2a573110073120002720993e4c6b2a5731300040eb2720a73140093e4c6b2a5731500050eb2720a73160093e4c6b2a5731700060eb2720a73180093e4c6b2a5731900070eb2720a731a0093e4c6b2a5731b00080eb2720a731c0093e4c6b2a5731d00090eb2720a731e00731f";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UtxoResponse {
    items: Vec<ErgoBox>,
    total: u32,
}

async fn get_current_state_context(client: &Client) -> Result<ErgoStateContext, reqwest::Error> {
    let url = format!("{NODE_ADDRESS}/blocks/lastHeaders/10");

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
    let url = format!("{NODE_ADDRESS}/transactions");

    client
        .post(&url)
        .json(transaction)
        .send()
        .await?
        .json::<ApiResponse<String>>()
        .await
}

const SEARCH_STEP: usize = 64;

fn calculate_loop(
    work_queue: Receiver<(CytiCalculateRequest, usize, usize)>,
    reply_queue: Sender<(Vec<u8>, f64)>,
) {
    while let Ok((request, from, to)) = work_queue.recv() {
        let num_guesses = AtomicU64::new(0);
        let now = std::time::Instant::now();
        let bytes = (from..to)
            .into_par_iter()
            .step_by(SEARCH_STEP)
            .find_map_any(|guess| {
                let (solution, guesses) =
                    request.calculate_range(guess as u64, (guess + SEARCH_STEP - 1) as u64);
                num_guesses.fetch_add(guesses, Ordering::Relaxed);
                solution
            });
        let hash_rate = num_guesses.load(Ordering::Relaxed) as f64 / now.elapsed().as_secs_f64();
        if let Some(bytes) = bytes {
            if let Err(SendError(_)) = reply_queue.send((bytes, hash_rate)) {
                break;
            }
        }
    }
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init_timed();

    let (send_work, recv_work) = channel();

    let (send_solved, recv_solved) = channel();

    let _ = spawn(|| calculate_loop(recv_work, send_solved));

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

        let request_hex: String = request_id.into_iter().map(|c| format!("{c:02x}")).collect();

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

        let request = CytiCalculateRequest::new(&request, creation_height, &miner_address).unwrap();

        send_work.send((request, 0, u64::MAX as usize)).unwrap();

        let solved_tx = Some(recv_solved.recv().unwrap());

        if let Some((solved_tx, guess_rate)) = solved_tx {
            info!("Hashrate: {:.3}", guess_rate);
            let solved_tx = Transaction::sigma_parse_bytes(&solved_tx).unwrap();

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
