mod cache_db;

use std::ops::MulAssign;
use revm::{
    primitives::{
        address, keccak256, AccountInfo, Address, Bytes, ExecutionResult, Output, TxKind, U256,
    },
    Evm,
};
use alloy_sol_types::{SolCall, SolValue};
use alloy_sol_macro::sol;
use alloy::{
    hex,
    rpc::types::TransactionRequest,

};

use anyhow::{anyhow, Result};
use revm::handler::mainnet::output;
use revm::primitives::{Bytecode, CANCUN, LATEST};
use crate::cache_db::CacheDB;

const ONE_ETH: u128 = 1_000_000_000_000_000_000u128;
const ONE_B: u128 = 1_000_000_000u128;
// const ONE_K_ETH : U256 = ONE_ETH.wrapping_mul(ONE_K);
//max fee?? 1_000_000_000_000_000_000,
struct StatefulEvm {
    pub db: CacheDB,
    //pub evm : Evm<>
    pub addresses: Vec<Address>,
}


// The address for an Ethereum contract is deterministically computed from the address of
// its creator ( sender ) and how many transactions the creator has sent ( nonce ).
// The sender and nonce are RLP encoded and then hashed with Keccak-256


impl StatefulEvm {
    pub fn new() -> Self {
        let mut sevm = StatefulEvm {
            db: CacheDB::default(),
            addresses: Vec::new(),
        };
        let mut alice = (address!("1234567890123456789012345678900000000000"), AccountInfo::default());
        alice.1.balance = U256::from(ONE_ETH * ONE_B);
        let mut bob = (address!("1234567890123456789012345678900000000001"), AccountInfo::default());
        bob.1.balance = U256::from(ONE_ETH * ONE_B);
        sevm.db.insert_account_info(alice.0, alice.1);
        sevm.db.insert_account_info(bob.0, bob.1);
        sevm.addresses.push(alice.0);
        sevm.addresses.push(bob.0);
        sevm
    }

    pub fn add_contract(&mut self,
                        from: Address,
                        // nonce: u64,
                        contract: Bytes
    ) -> Option<Address> {
        let mut evm = Evm::builder()
            .with_db(&mut self.db)
            .with_spec_id(LATEST)
            .modify_tx_env(|tx| {
                tx.caller = from;
                tx.transact_to = TxKind::Create;
                tx.data = contract;
                tx.value = U256::from(0);
            })
            .build();

        let ref_tx = evm.transact_commit().unwrap();
        match ref_tx {
            ExecutionResult::Success {
                output: Output::Create(_, address),
                ..
            } => {
                println!("contract address: {:?}", address.unwrap());
                return address;
            },
            result => {
                println!("'create' execution failed: {result:?}");
                return None;
            },
        };
    }

    fn transfer(&mut self,
                token: Address,
                from: Address,
                recipient: Address,
                amount: U256,
    ) {
        sol! {function transfer(address recipient, uint256 amount)
            external
            returns (bool);
        }
        let encoded = transferCall { recipient, amount }.abi_encode();

        let mut evm = Evm::builder()
            .with_db(&mut self.db)
            .modify_tx_env(|tx| {
                tx.caller = from;
                tx.transact_to = TxKind::Call(token);
                tx.data = encoded.into();
                tx.value = U256::ZERO;
            })
            .build();

        let ref_tx = evm.transact_commit().unwrap();
        match ref_tx {
            ExecutionResult::Success {
                gas_used,
                output: Output::Call(value),
                ..
            } => {},//println!("transfer gas used: {:?}, {:?}", gas_used, value),
            result => println!("'transfer' execution failed: {result:?}"),
        };
    }

    fn balance_of(&mut self, token: Address, address: Address) -> U256 {
        sol! {
            function balanceOf(address account) public returns (uint256);
        }

        let encoded = balanceOfCall { account: address }.abi_encode();

        let mut evm = Evm::builder()
            .with_db(&mut self.db)
            .modify_tx_env(|tx| {
                // 0x1 because calling USDC proxy from zero address fails
                tx.caller = address;
                tx.transact_to = TxKind::Call(token);
                tx.data = encoded.into();
                tx.value = U256::from(0);
            })
            .build();

        let ref_tx = evm.transact().unwrap();
        let result = ref_tx.result;

        let value = match result {
            ExecutionResult::Success {
                output: Output::Call(value),
            ..
            } => value,
            result => return U256::ZERO,
        };

        <U256>::abi_decode(&value, false).expect("decode")
    }

    fn eth_transfer(&mut self,
                    from: Address,
                    to: Address,
                    amount: U256,
    ) {
        let mut evm = Evm::builder()
            .with_db(&mut self.db)
            .modify_tx_env(|tx| {
                tx.caller = from;
                tx.transact_to = TxKind::Call(to);
                tx.data = Bytes::default();
                tx.value = amount;
            })
            .build();

        let ref_tx = evm.transact_commit().unwrap();
        match ref_tx {
            ExecutionResult::Success {
                gas_used,
                ..
            } => {},//println!("transfer gas used: {:?}", gas_used),
            result => println!("'transfer' execution failed: {result:?}"),
        };
    }
    pub fn eth_balance(&mut self, address: &Address) -> U256 {
        match self.db.accounts.get(address){
            Some(acc) => acc.info.balance,
            _ => U256::from(0)
        }
    }
}

fn transact() {
    let mut cs = StatefulEvm::new();
    let a = cs.addresses[0];
    let b = cs.addresses[1];
    println!("a eth: {}", cs.eth_balance(&a));
    println!("b eth: {}", cs.eth_balance(&b));

    cs.eth_transfer(a, b, U256::from(ONE_ETH));
    println!("a eth: {}", cs.eth_balance(&a));
    println!("b eth: {}", cs.eth_balance(&b));

    cs.eth_transfer(a, b, U256::from(ONE_ETH));
    println!("a eth: {}", cs.eth_balance(&a));
    println!("b eth: {}", cs.eth_balance(&b));

    let bytecode = hex::decode("608060405234801561000f575f5ffd5b506040518060400160405280600b81526020017f746573746e65745f7872700000000000000000000000000000000000000000008152506040518060400160405280600381526020017f58525000000000000000000000000000000000000000000000000000000000008152506002826003908161008d91906103e3565b50816004908161009d91906103e3565b508060055f6101000a81548160ff021916908360ff1602179055505050506100ce33620f42406100d360201b60201c565b61053a565b8060015f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825461011f91906104df565b92505081905550805f5f82825461013691906104df565b925050819055508173ffffffffffffffffffffffffffffffffffffffff165f73ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef8360405161019a9190610521565b60405180910390a35050565b5f81519050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f600282049050600182168061022157607f821691505b602082108103610234576102336101dd565b5b50919050565b5f819050815f5260205f209050919050565b5f6020601f8301049050919050565b5f82821b905092915050565b5f600883026102967fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8261025b565b6102a0868361025b565b95508019841693508086168417925050509392505050565b5f819050919050565b5f819050919050565b5f6102e46102df6102da846102b8565b6102c1565b6102b8565b9050919050565b5f819050919050565b6102fd836102ca565b610311610309826102eb565b848454610267565b825550505050565b5f5f905090565b610328610319565b6103338184846102f4565b505050565b5b818110156103565761034b5f82610320565b600181019050610339565b5050565b601f82111561039b5761036c8161023a565b6103758461024c565b81016020851015610384578190505b6103986103908561024c565b830182610338565b50505b505050565b5f82821c905092915050565b5f6103bb5f19846008026103a0565b1980831691505092915050565b5f6103d383836103ac565b9150826002028217905092915050565b6103ec826101a6565b67ffffffffffffffff811115610405576104046101b0565b5b61040f825461020a565b61041a82828561035a565b5f60209050601f83116001811461044b575f8415610439578287015190505b61044385826103c8565b8655506104aa565b601f1984166104598661023a565b5f5b828110156104805784890151825560018201915060208501945060208101905061045b565b8683101561049d5784890151610499601f8916826103ac565b8355505b6001600288020188555050505b505050505050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6104e9826102b8565b91506104f4836102b8565b925082820190508082111561050c5761050b6104b2565b5b92915050565b61051b816102b8565b82525050565b5f6020820190506105345f830184610512565b92915050565b610cb0806105475f395ff3fe608060405234801561000f575f5ffd5b50600436106100a7575f3560e01c806340c10f191161006f57806340c10f191461016557806370a082311461018157806395d89b41146101b15780639dc29fac146101cf578063a9059cbb146101eb578063dd62ed3e1461021b576100a7565b806306fdde03146100ab578063095ea7b3146100c957806318160ddd146100f957806323b872dd14610117578063313ce56714610147575b5f5ffd5b6100b361024b565b6040516100c09190610989565b60405180910390f35b6100e360048036038101906100de9190610a3a565b6102d7565b6040516100f09190610a92565b60405180910390f35b6101016103c4565b60405161010e9190610aba565b60405180910390f35b610131600480360381019061012c9190610ad3565b6103c9565b60405161013e9190610a92565b60405180910390f35b61014f61056e565b60405161015c9190610b3e565b60405180910390f35b61017f600480360381019061017a9190610a3a565b610580565b005b61019b60048036038101906101969190610b57565b61058e565b6040516101a89190610aba565b60405180910390f35b6101b96105a3565b6040516101c69190610989565b60405180910390f35b6101e960048036038101906101e49190610a3a565b61062f565b005b61020560048036038101906102009190610a3a565b61063d565b6040516102129190610a92565b60405180910390f35b61023560048036038101906102309190610b82565b610753565b6040516102429190610aba565b60405180910390f35b6003805461025890610bed565b80601f016020809104026020016040519081016040528092919081815260200182805461028490610bed565b80156102cf5780601f106102a6576101008083540402835291602001916102cf565b820191905f5260205f20905b8154815290600101906020018083116102b257829003601f168201915b505050505081565b5f8160025f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040516103b29190610aba565b60405180910390a36001905092915050565b5f5481565b5f8160025f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546104519190610c4a565b925050819055508160015f8673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546104a49190610c4a565b925050819055508160015f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546104f79190610c7d565b925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef8460405161055b9190610aba565b60405180910390a3600190509392505050565b60055f9054906101000a900460ff1681565b61058a8282610773565b5050565b6001602052805f5260405f205f915090505481565b600480546105b090610bed565b80601f01602080910402602001604051908101604052809291908181526020018280546105dc90610bed565b80156106275780601f106105fe57610100808354040283529160200191610627565b820191905f5260205f20905b81548152906001019060200180831161060a57829003601f168201915b505050505081565b6106398282610846565b5050565b5f8160015f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825461068a9190610c4a565b925050819055508160015f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546106dd9190610c7d565b925050819055508273ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516107419190610aba565b60405180910390a36001905092915050565b6002602052815f5260405f20602052805f5260405f205f91509150505481565b8060015f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546107bf9190610c7d565b92505081905550805f5f8282546107d69190610c7d565b925050819055508173ffffffffffffffffffffffffffffffffffffffff165f73ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef8360405161083a9190610aba565b60405180910390a35050565b8060015f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546108929190610c4a565b92505081905550805f5f8282546108a99190610c4a565b925050819055505f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef8360405161090d9190610aba565b60405180910390a35050565b5f81519050919050565b5f82825260208201905092915050565b8281835e5f83830152505050565b5f601f19601f8301169050919050565b5f61095b82610919565b6109658185610923565b9350610975818560208601610933565b61097e81610941565b840191505092915050565b5f6020820190508181035f8301526109a18184610951565b905092915050565b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6109d6826109ad565b9050919050565b6109e6816109cc565b81146109f0575f5ffd5b50565b5f81359050610a01816109dd565b92915050565b5f819050919050565b610a1981610a07565b8114610a23575f5ffd5b50565b5f81359050610a3481610a10565b92915050565b5f5f60408385031215610a5057610a4f6109a9565b5b5f610a5d858286016109f3565b9250506020610a6e85828601610a26565b9150509250929050565b5f8115159050919050565b610a8c81610a78565b82525050565b5f602082019050610aa55f830184610a83565b92915050565b610ab481610a07565b82525050565b5f602082019050610acd5f830184610aab565b92915050565b5f5f5f60608486031215610aea57610ae96109a9565b5b5f610af7868287016109f3565b9350506020610b08868287016109f3565b9250506040610b1986828701610a26565b9150509250925092565b5f60ff82169050919050565b610b3881610b23565b82525050565b5f602082019050610b515f830184610b2f565b92915050565b5f60208284031215610b6c57610b6b6109a9565b5b5f610b79848285016109f3565b91505092915050565b5f5f60408385031215610b9857610b976109a9565b5b5f610ba5858286016109f3565b9250506020610bb6858286016109f3565b9150509250929050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f6002820490506001821680610c0457607f821691505b602082108103610c1757610c16610bc0565b5b50919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f610c5482610a07565b9150610c5f83610a07565b9250828203905081811115610c7757610c76610c1d565b5b92915050565b5f610c8782610a07565b9150610c9283610a07565b9250828201905080821115610caa57610ca9610c1d565b5b9291505056");
    let code = Bytes::from(bytecode.unwrap());
    let contract_addr = cs.add_contract(a, code).unwrap();
    println!("a eth: {}", cs.eth_balance(&a));

    println!("a balance {:?}", cs.balance_of(contract_addr, a));
    println!("b balance {:?}", cs.balance_of(contract_addr, b));

    cs.transfer(contract_addr,a,b,U256::from(100));
    println!("a balance {:?}", cs.balance_of(contract_addr, a));
    println!("b balance {:?}", cs.balance_of(contract_addr, b));

    cs.transfer(contract_addr,a,b,U256::from(100));
    println!("a balance {:?}", cs.balance_of(contract_addr, a));
    println!("b balance {:?}", cs.balance_of(contract_addr, b));

    println!("transact() done!");
}

fn main() {
    transact();
}
