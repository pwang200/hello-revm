// use revm::{DatabaseCommit, DatabaseRef, EmptyDB};
// use revm_primitives::db::DatabaseCommit;
// use revm::DatabaseCommit;
use revm::primitives::{
    Account, AccountInfo, Address, Bytecode, Log, B256, KECCAK_EMPTY,
    U256,
};
// use crate::Database;
// use core::convert::Infallible;
// use std::vec::Vec;
use serde::{Deserialize, Serialize};
use postcard::{from_bytes, to_allocvec};
// use alloc::vec::Vec;
use std::collections::{HashMap, hash_map::Entry};
// use std::fmt;
use revm::{Database, DatabaseCommit, DatabaseRef};
use revm_primitives::{Bytes, keccak256};


type VecU8 = Vec<u8>;

#[derive(Debug, Clone)]
pub enum DBError {
    // NotExist,
    BadData,
}

// Generation of an error is completely separate from how it is displayed.
// There's no need to be concerned about cluttering complex logic with the display style.
//
// Note that we don't store any extra info about the errors. This means we can't state
// which string failed to parse without modifying our types to carry that information.
// impl fmt::Display for DBError {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "invalid first item to double")
//     }
// }

#[derive(Debug, Clone, Default)]
pub struct BytesDB {
    /// Account info where None means it is not existing. Not existing state is needed for Pre TANGERINE forks.
    /// `code` is always `None`, and bytecode can be found in `contracts`.
    pub accounts: HashMap<Address, VecU8>,
    /// Tracks all contracts by their code hash.
    pub contracts: HashMap<B256, VecU8>,
    /// All cached block hashes from the [DatabaseRef].
    pub block_hashes: HashMap<U256, B256>,
    pub account_storage: HashMap<Address, HashMap<U256, U256>>,
}

impl BytesDB {
    pub fn insert_contract(&mut self, account: &AccountInfo) {
        self.contracts
            .entry(account.code_hash)
            .or_insert_with(|| account.code.clone().unwrap().bytes_slice().to_vec());
        // if self.contracts.contains_key(&account.code_hash){
        //     return false;
        // }
        // let code = account.code.clone().unwrap().bytes_slice().to_vec();
        // return true;
    }

    //Consider use the same serialization for code and info
    pub fn insert_account_info(&mut self, address: Address, info: &AccountInfo) {
        self.accounts
            .entry(address)
            .or_insert_with(|| to_allocvec(&info).unwrap());
    }

    pub fn get_account_info(&self, address: &Address) -> Result<Option<AccountInfo>, DBError> {
        if self.accounts.contains_key(address) {
            let data = self.accounts.get(address).unwrap();
            let info: AccountInfo = from_bytes(data).unwrap();
            return Ok(Some(info));
        }
        Ok(None)//Err(DBError::NotExist)
    }

    pub fn insert_account_storage(&mut self, address: Address, slot: U256, value: U256) -> Result<(), DBError> {
        self.account_storage.entry(address).or_default().insert(slot, value);
        Ok(())
    }

    pub fn replace_account_storage(&mut self, address: Address, storage: HashMap<U256, U256>) -> Result<(), DBError> {
        *self.account_storage.entry(address).or_default() = storage;
        Ok(())
    }

    pub fn code_by_hash(&self, code_hash: B256) -> Result<Bytecode, DBError> {
        match self.contracts.get(&code_hash) {
            Some(entry) => Ok(Bytecode::new_raw(Bytes::from(entry.clone()))),
            None => Ok(Bytecode::default()),//Err(DBError::NotExist),
        }
    }

    pub fn storage(&self, address: Address, index: U256) -> Result<U256, DBError> {
        match self.account_storage.get(&address) {
            None => { return Ok(U256::default()); }//Err(DBError::NotExist)}
            Some(storage) => {
                match storage.get(&index) {
                    None => { return Ok(U256::default()); }//Err(DBError::NotExist)}
                    Some(value) => {
                        return Ok(value.clone());
                    }
                }
            }
        }
    }

    // fn basic(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
    //     match self.accounts.get(&address) {
    //         Some(acc) => Ok(acc.info()),
    //         None => self.db.basic_ref(address),
    //     }
    // }

    fn block_hash(&self, number: u64) -> Result<B256, DBError> {
        match self.block_hashes.get(&U256::from(number)) {
            Some(entry) => Ok(*entry),
            None => Ok(keccak256(number.to_string().as_bytes()))//Err(DBError::NotExist),
        }
    }
}

/// A [Database] implementation that stores all state changes in memory.
///
/// This implementation wraps a [DatabaseRef] that is used to load data ([AccountInfo]).
///
/// Accounts and code are stored in two separate maps, the `accounts` map maps addresses to [DbAccount],
/// whereas contracts are identified by their code hash, and are stored in the `contracts` map.
/// The [DbAccount] holds the code hash of the contract, which is used to look up the contract in the `contracts` map.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CacheDB {
    /// Account info where None means it is not existing. Not existing state is needed for Pre TANGERINE forks.
    /// `code` is always `None`, and bytecode can be found in `contracts`.
    pub accounts: HashMap<Address, DbAccount>,
    /// Tracks all contracts by their code hash.
    pub contracts: HashMap<B256, Bytecode>,
    /// All logs that were committed via [DatabaseCommit::commit].
    pub logs: Vec<Log>,
    /// All cached block hashes from the [DatabaseRef].
    pub block_hashes: HashMap<U256, B256>,
    /// The underlying database that is used to load data.
    pub db: BytesDB,
}

impl Default for CacheDB {
    fn default() -> Self {
        let mut db = BytesDB::default();
        db.insert_account_info(Address::ZERO, &AccountInfo::default());
        Self::new(db)
    }
}

impl CacheDB {
    pub fn new(db: BytesDB) -> Self {
        let mut contracts = HashMap::new();
        contracts.insert(KECCAK_EMPTY, Bytecode::default());
        contracts.insert(B256::ZERO, Bytecode::default());

        let mut accounts = HashMap::new();
        accounts.insert(Address::ZERO, DbAccount::default());
        Self {
            accounts,
            contracts,
            logs: Vec::default(),
            block_hashes: HashMap::new(),
            db,
        }
    }

    /// Inserts the account's code into the cache.
    ///
    /// Accounts objects and code are stored separately in the cache,
    /// this will take the code from the account and instead map it to the code hash.
    pub fn insert_contract(&mut self, account: &mut AccountInfo) {
        if account.code_hash.is_zero() {
            account.code_hash = KECCAK_EMPTY;
        }
        if let Some(code) = &account.code {
            if !code.is_empty() {
                if account.code_hash == KECCAK_EMPTY {
                    account.code_hash = code.hash_slow();
                }
                self.contracts
                    .entry(account.code_hash)
                    .or_insert_with(|| code.clone());
                self.db.insert_contract(account);
            }
        }
        // account.code = None;//TODO
    }

    /// Insert account info but not override storage
    pub fn insert_account_info(&mut self, address: Address, mut info: AccountInfo) {
        self.insert_contract(&mut info);
        self.db.insert_account_info(address, &info);
        self.accounts.entry(address).or_default().info = info;
    }

    /// Returns the account for the given address.
    ///
    /// If the account was not found in the cache, it will be loaded from the underlying database.
    pub fn load_account(&mut self, address: Address) -> Result<&mut DbAccount, DBError> {
        let db = &self.db;
        match self.accounts.entry(address) {
            Entry::Occupied(entry) => Ok(entry.into_mut()),
            Entry::Vacant(entry) => Ok(
                entry.insert(
                    db.get_account_info(&address)?
                        .map(|info| DbAccount {
                            info,
                            ..Default::default()
                        })
                        .unwrap_or_else(DbAccount::new_not_existing),
                )),
        }
    }

    /// insert account storage without overriding account info
    pub fn insert_account_storage(&mut self, address: Address, slot: U256, value: U256) -> Result<(), DBError> {
        self.db.insert_account_storage(address, slot, value)?;
        let account = self.load_account(address)?;
        account.storage.insert(slot, value);
        Ok(())
    }

    /// replace account storage without overriding account info
    pub fn replace_account_storage(&mut self, address: Address, storage: HashMap<U256, U256>) -> Result<(), DBError> {
        self.db.replace_account_storage(address, storage.clone())?;
        let account = self.load_account(address)?;
        account.account_state = AccountState::StorageCleared;
        account.storage = storage.into_iter().collect();
        Ok(())
    }
}

impl DatabaseCommit for CacheDB {
    fn commit(&mut self, changes: HashMap<Address, Account>) {
        for (address, mut account) in changes {
            if !account.is_touched() {
                continue;
            }
            if account.is_selfdestructed() {
                let db_account = self.accounts.entry(address).or_default();
                db_account.storage.clear();
                db_account.account_state = AccountState::NotExisting;
                db_account.info = AccountInfo::default();
                //TODO clear db
                continue;
            }
            let is_newly_created = account.is_created();
            self.insert_contract(&mut account.info);

            let db_account = self.accounts.entry(address).or_default();
            db_account.info = account.info;

            db_account.account_state = if is_newly_created {
                db_account.storage.clear();
                AccountState::StorageCleared
            } else if db_account.account_state.is_storage_cleared() {
                // Preserve old account state if it already exists
                AccountState::StorageCleared
            } else {
                AccountState::Touched
            };
            db_account.storage.extend(
                account
                    .storage
                    .into_iter()
                    .map(|(key, value)| (key, value.present_value())),
            );
        }
    }
}

impl Database for CacheDB {
    type Error = DBError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, DBError> {
        let basic = match self.accounts.entry(address) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(
                self.db.get_account_info(&address)?
                    // .basic_ref(address)?
                    .map(|info| DbAccount {
                        info,
                        ..Default::default()
                    })
                    .unwrap_or_else(DbAccount::new_not_existing),
            ),
        };
        Ok(basic.info())
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, DBError> {
        match self.contracts.entry(code_hash) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                // if you return code bytes when basic fn is called this function is not needed.
                Ok(entry.insert(self.db.code_by_hash(code_hash)?).clone())
            }
        }
    }

    /// Get the value in an account's storage slot.
    ///
    /// It is assumed that account is already loaded.
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, DBError> {
        match self.accounts.entry(address) {
            Entry::Occupied(mut acc_entry) => {
                let acc_entry = acc_entry.get_mut();
                match acc_entry.storage.entry(index) {
                    Entry::Occupied(entry) => Ok(*entry.get()),
                    Entry::Vacant(entry) => {
                        if matches!(
                            acc_entry.account_state,
                            AccountState::StorageCleared | AccountState::NotExisting
                        ) {
                            Ok(U256::ZERO)
                        } else {
                            let slot = self.db.storage(address, index)?;
                            entry.insert(slot);
                            Ok(slot)
                        }
                    }
                }
            }
            Entry::Vacant(acc_entry) => {
                // acc needs to be loaded for us to access slots.
                let info = self.db.get_account_info(&address)?;
                let (account, value) = if info.is_some() {
                    let value = self.db.storage(address, index)?;
                    let mut account: DbAccount = info.into();
                    account.storage.insert(index, value);
                    (account, value)
                } else {
                    (info.into(), U256::ZERO)
                };
                acc_entry.insert(account);
                Ok(value)
            }
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, DBError> {
        match self.block_hashes.entry(U256::from(number)) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                let hash = self.db.block_hash(number)?;
                entry.insert(hash);
                Ok(hash)
            }
        }
    }
}

impl DatabaseRef for CacheDB {
    type Error = DBError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, DBError> {
        match self.accounts.get(&address) {
            Some(acc) => Ok(acc.info()),
            None => self.db.get_account_info(&address),
        }
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, DBError> {
        match self.contracts.get(&code_hash) {
            Some(entry) => Ok(entry.clone()),
            None => self.db.code_by_hash(code_hash),
        }
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, DBError> {
        match self.accounts.get(&address) {
            Some(acc_entry) => match acc_entry.storage.get(&index) {
                Some(entry) => Ok(*entry),
                None => {
                    if matches!(
                        acc_entry.account_state,
                        AccountState::StorageCleared | AccountState::NotExisting
                    ) {
                        Ok(U256::ZERO)
                    } else {
                        self.db.storage(address, index)
                    }
                }
            },
            None => self.db.storage(address, index),
        }
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, DBError> {
        match self.block_hashes.get(&U256::from(number)) {
            Some(entry) => Ok(*entry),
            None => self.db.block_hash(number),
        }
    }
}

#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DbAccount {
    pub info: AccountInfo,
    /// If account is selfdestructed or newly created, storage will be cleared.
    pub account_state: AccountState,
    /// storage slots
    pub storage: HashMap<U256, U256>,
}

impl DbAccount {
    pub fn new_not_existing() -> Self {
        Self {
            account_state: AccountState::NotExisting,
            ..Default::default()
        }
    }

    pub fn info(&self) -> Option<AccountInfo> {
        if matches!(self.account_state, AccountState::NotExisting) {
            None
        } else {
            Some(self.info.clone())
        }
    }
}

impl From<Option<AccountInfo>> for DbAccount {
    fn from(from: Option<AccountInfo>) -> Self {
        from.map(Self::from).unwrap_or_else(Self::new_not_existing)
    }
}

impl From<AccountInfo> for DbAccount {
    fn from(info: AccountInfo) -> Self {
        Self {
            info,
            account_state: AccountState::None,
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum AccountState {
    /// Before Spurious Dragon hardfork there was a difference between empty and not existing.
    /// And we are flagging it here.
    NotExisting,
    /// EVM touched this account. For newer hardfork this means it can be cleared/removed from state.
    Touched,
    /// EVM cleared storage of this account, mostly by selfdestruct, we don't ask database for storage slots
    /// and assume they are U256::ZERO
    StorageCleared,
    /// EVM didn't interacted with this account
    #[default]
    None,
}

impl AccountState {
    /// Returns `true` if EVM cleared storage of this account
    pub fn is_storage_cleared(&self) -> bool {
        matches!(self, AccountState::StorageCleared)
    }
}

#[cfg(test)]
mod tests {
    // use bytes::Bytes;
    use super::{CacheDB, BytesDB};
    use revm::{
        Database,
        primitives::{AccountInfo, Address, U256},
    };
    use revm_primitives::{Bytes, Bytecode};

    #[test]
    fn test_bytesdb_load() {
        let mut persist = BytesDB::default();
        // account info
        let addr = Address::with_last_byte(42);
        let nonce = 42;
        // account info with bytecode
        let b = Bytes::from("608060405234");
        let bc = Bytecode::new_raw(Bytes::from(b.clone()));
        let bch = bc.hash_slow();
        let info = AccountInfo {
            nonce,
            code_hash: bch,
            code: Some(bc.clone()),
            ..Default::default()
        };
        persist.insert_account_info(
            addr,
            &info,
        );
        // storage
        let (key, value) = (U256::from(123), U256::from(456));
        persist.insert_account_storage(addr, key, value).unwrap();
        // bytecode
        persist.insert_contract(&info);

        // retrieve
        let info_db = persist.get_account_info(&addr).unwrap().unwrap();
        let nonce_db = info_db.nonce;
        let value_db = persist.storage(addr, key).unwrap();
        let code = info_db.code.unwrap();
        let raw = code.bytes();
        let code_seperate = persist.code_by_hash(bch).unwrap();
        assert_eq!(nonce_db, nonce);
        assert_eq!(value_db, value);
        assert_eq!(bc, code);
        assert_eq!(raw, b);
        assert_eq!(code_seperate, code);
        println!("test_bytesdb_load: {:?} {:?} {:?} {:?} {:?}", nonce_db, value_db, code, raw, code_seperate);
    }

    #[test]
    fn test_cachedb_load() {
        let persist = BytesDB::default();
        let mut cache = CacheDB::new(persist);

        // account info
        let addr = Address::with_last_byte(42);
        let nonce = 42;
        // account info with bytecode
        let b = Bytes::from("608060405234");
        let bc = Bytecode::new_raw(Bytes::from(b.clone()));
        let bch = bc.hash_slow();
        let mut info = AccountInfo {
            nonce,
            code_hash: bch,
            code: Some(bc.clone()),
            ..Default::default()
        };

        cache.insert_account_info(
            addr,
            info.clone(),
        );

        // storage
        let (key, value) = (U256::from(123), U256::from(456));
        cache.insert_account_storage(addr, key, value).unwrap();
        // bytecode
        cache.insert_contract(&mut info);

        // retrieve
        let account_db = cache.load_account(addr).unwrap();
        let nonce_db = account_db.info.nonce;
        let code = account_db.info.code.clone().unwrap();
        let value_db = cache.storage(addr, key).unwrap();
        let raw = code.bytes();
        let code_seperate = cache.code_by_hash(bch).unwrap();
        assert_eq!(nonce_db, nonce);
        assert_eq!(value_db, value);
        assert_eq!(bc, code);
        assert_eq!(raw, b);
        assert_eq!(code_seperate, code);
        println!("test_cachedb_load: {:?} {:?} {:?} {:?} {:?}", nonce_db, value_db, code, raw, code_seperate);
    }

    #[test]
    fn test_persist_cachedb_load() {
        let persist = BytesDB::default();
        let mut cache = CacheDB::new(persist);

        // account info
        let addr = Address::with_last_byte(42);
        let nonce = 42;
        // account info with bytecode
        let b = Bytes::from("608060405234");
        let bc = Bytecode::new_raw(Bytes::from(b.clone()));
        let bch = bc.hash_slow();
        let mut info = AccountInfo {
            nonce,
            code_hash: bch,
            code: Some(bc.clone()),
            ..Default::default()
        };

        cache.insert_account_info(
            addr,
            info.clone(),
        );

        // storage
        let (key, value) = (U256::from(123), U256::from(456));
        cache.insert_account_storage(addr, key, value).unwrap();
        // bytecode
        cache.insert_contract(&mut info);

        // take the persist db and recreate cache db
        let persist = cache.db;
        let mut cache = CacheDB::new(persist);

        // retrieve
        let account_db = cache.load_account(addr).unwrap();
        let nonce_db = account_db.info.nonce;
        let code = account_db.info.code.clone().unwrap();
        let value_db = cache.storage(addr, key).unwrap();
        let raw = code.bytes();
        let code_seperate = cache.code_by_hash(bch).unwrap();
        assert_eq!(nonce_db, nonce);
        assert_eq!(value_db, value);
        assert_eq!(bc, code);
        assert_eq!(raw, b);
        assert_eq!(code_seperate, code);
        println!("test_persist_cachedb_load: {:?} {:?} {:?} {:?} {:?}", nonce_db, value_db, code, raw, code_seperate);
    }
}
