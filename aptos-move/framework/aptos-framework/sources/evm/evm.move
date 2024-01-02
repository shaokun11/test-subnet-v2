module aptos_framework::evm {
    friend aptos_framework::genesis;

    #[test_only]
    use aptos_framework::account;
    use aptos_framework::account::{exists_at, new_event_handle};
    use std::vector;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_std::secp256k1::{ecdsa_recover, ecdsa_signature_from_bytes, ecdsa_raw_public_key_to_bytes};
    use std::option::borrow;
    use aptos_std::aptos_hash::{keccak256};
    use aptos_framework::create_signer::create_signer;
    #[test_only]
    use std::string;
    use aptos_framework::aptos_account::create_account;
    use aptos_std::debug;
    use std::signer::address_of;
    use aptos_framework::evm_util::{slice, to_32bit, get_contract_address, power, to_int256, data_to_u256, u256_to_data, mstore, u256_to_trimed_data, to_u256};
    use aptos_framework::timestamp::now_microseconds;
    use aptos_framework::block;
    use std::string::utf8;
    use aptos_framework::event::EventHandle;
    use aptos_framework::event;
    use aptos_std::table;
    use aptos_std::table::Table;
    use aptos_framework::rlp_decode::{decode_bytes_list};
    use aptos_std::from_bcs::{to_address};
    use std::bcs::to_bytes;
    use aptos_framework::rlp_encode::encode_bytes_list;
    #[test_only]
    use aptos_framework::account::create_account_for_test;
    use aptos_framework::delegate::execute_move_tx;
    #[test_only]
    use aptos_framework::multisig_account::{get_next_multisig_account_address, create_with_owners, create_transaction, can_be_executed};
    #[test_only]
    use std::features;
    #[test_only]
    use aptos_framework::timestamp;
    #[test_only]
    use aptos_framework::chain_id;

    const TX_TYPE_LEGACY: u64 = 1;

    const ADDR_LENGTH: u64 = 10001;
    const SIGNATURE: u64 = 10002;
    const INSUFFIENT_BALANCE: u64 = 10003;
    const NONCE: u64 = 10004;
    const CONTRACT_READ_ONLY: u64 = 10005;
    const CREATE2_CONTRACT_DEPLOYED: u64 = 10006;
    const CREATE_CONTRACT_DEPLOYED: u64 = 10007;
    const TX_NOT_SUPPORT: u64 = 10008;
    const ACCOUNT_NOT_EXIST: u64 = 10009;
    const PRECOMPILE_SELECTOR: u64 = 10010;
    const CONVERT_BASE: u256 = 10000000000;
    const CHAIN_ID: u64 = 0x150;

    const U256_MAX: u256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935;
    const ZERO_ADDR: vector<u8> =      x"0000000000000000000000000000000000000000000000000000000000000000";
    const DEPLOY_ADDR: vector<u8> =      x"0000000000000000000000000000000000000000000000000000000000000100";
    const PRECOMPILE_ADDR: vector<u8> =      x"0000000000000000000000000000000000000000000000000000000000000101";
    const ONE_ADDR: vector<u8> =       x"0000000000000000000000000000000000000000000000000000000000000001";
    const CHAIN_ID_BYTES: vector<u8> = x"0150";

    // struct Acc

    struct Account has key {
        balance: u256,
        nonce: u64,
        is_contract: bool,
        code: vector<u8>,
        storage: Table<u256, vector<u8>>,
    }

    struct Log0Event has drop, store {
        contract: vector<u8>,
        data: vector<u8>
    }

    struct Log1Event has drop, store {
        contract: vector<u8>,
        data: vector<u8>,
        topic0: vector<u8>
    }

    struct Log2Event has drop, store {
        contract: vector<u8>,
        data: vector<u8>,
        topic0: vector<u8>,
        topic1: vector<u8>
    }

    struct Log3Event has drop, store {
        contract: vector<u8>,
        data: vector<u8>,
        topic0: vector<u8>,
        topic1: vector<u8>,
        topic2: vector<u8>
    }

    struct Log4Event has drop, store {
        contract: vector<u8>,
        data: vector<u8>,
        topic0: vector<u8>,
        topic1: vector<u8>,
        topic2: vector<u8>,
        topic3: vector<u8>
    }

    struct ContractEvent has key {
        log0Event: EventHandle<Log0Event>,
        log1Event: EventHandle<Log1Event>,
        log2Event: EventHandle<Log2Event>,
        log3Event: EventHandle<Log3Event>,
        log4Event: EventHandle<Log4Event>,
    }

    public(friend) fun initialize() acquires Account {
        let address_contract = to_address(PRECOMPILE_ADDR);
        create_account_if_not_exist(address_contract);
        create_event_if_not_exist(address_contract);
        borrow_global_mut<Account>(address_contract).is_contract = true;
    }

    public entry fun send_tx(
        sender: &signer,
        evm_from: vector<u8>,
        tx: vector<u8>,
        gas_bytes: vector<u8>,
        tx_type: u64,
    ) acquires Account, ContractEvent {
        let gas = to_u256(gas_bytes);
        if(tx_type == TX_TYPE_LEGACY) {
            let decoded = decode_bytes_list(&tx);
            // debug::print(&decoded);
            let nonce = to_u256(*vector::borrow(&decoded, 0));
            let gas_price = to_u256(*vector::borrow(&decoded, 1));
            let gas_limit = to_u256(*vector::borrow(&decoded, 2));
            let evm_to = *vector::borrow(&decoded, 3);
            let value = to_u256(*vector::borrow(&decoded, 4));
            let data = *vector::borrow(&decoded, 5);
            let v = (to_u256(*vector::borrow(&decoded, 6)) as u64);
            let r = *vector::borrow(&decoded, 7);
            let s = *vector::borrow(&decoded, 8);

            let message = if(v > 28) encode_bytes_list(vector[
                u256_to_trimed_data(nonce),
                u256_to_trimed_data(gas_price),
                u256_to_trimed_data(gas_limit),
                evm_to,
                u256_to_trimed_data(value),
                data,
                CHAIN_ID_BYTES,
                x"",
                x""
            ]) else encode_bytes_list(vector[
                u256_to_trimed_data(nonce),
                u256_to_trimed_data(gas_price),
                u256_to_trimed_data(gas_limit),
                evm_to,
                u256_to_trimed_data(value),
                data
            ]);
            let message_hash = keccak256(message);
            verify_signature(evm_from, message_hash, to_32bit(r), to_32bit(s), v);
            evm_to = to_32bit(evm_to);
            evm_to = if(evm_to == ZERO_ADDR) DEPLOY_ADDR else evm_to;
            execute(to_32bit(evm_from), evm_to, (nonce as u64), data, value);
            transfer_to_move_addr(to_32bit(evm_from), address_of(sender), gas * CONVERT_BASE);
        } else {
            assert!(false, TX_NOT_SUPPORT);
        }
    }

    public entry fun send_move_tx_to_evm(
        sender: &signer,
        nonce: u64,
        evm_to: vector<u8>,
        value_bytes: vector<u8>,
        data: vector<u8>,
        tx_type: u64,
    ) acquires Account, ContractEvent {
        if(tx_type == TX_TYPE_LEGACY) {
            evm_to = to_32bit(evm_to);
            evm_to = if(evm_to == ZERO_ADDR) DEPLOY_ADDR else evm_to;
            let evm_from = slice(to_bytes(&address_of(sender)), 12, 20);
            execute(to_32bit(evm_from), evm_to, nonce, data, to_u256(value_bytes));
        } else {
            assert!(false, TX_NOT_SUPPORT);
        }
    }

    public entry fun estimate_tx_gas(
        evm_from: vector<u8>,
        evm_to: vector<u8>,
        data: vector<u8>,
        value_bytes: vector<u8>,
        tx_type: u64,
    ) acquires Account, ContractEvent {
        let value = to_u256(value_bytes);
        if(tx_type == TX_TYPE_LEGACY) {
            let address_from = to_address(to_32bit(evm_from));
            assert!(exists<Account>(address_from), ACCOUNT_NOT_EXIST);
            let nonce = borrow_global<Account>(address_from).nonce;
            execute(to_32bit(evm_from), to_32bit(evm_to), nonce, data, value);
        } else {
            assert!(false, TX_NOT_SUPPORT);
        }
    }

    public entry fun deposit(sender: &signer, evm_addr: vector<u8>, amount_bytes: vector<u8>) acquires Account {
        let amount = to_u256(amount_bytes);
        assert!(vector::length(&evm_addr) == 20, ADDR_LENGTH);
        transfer_from_move_addr(sender, to_32bit(evm_addr), amount);
    }

    #[view]
    public fun get_move_address(evm_addr: vector<u8>): address {
        to_address(to_32bit(evm_addr))
    }

    #[view]
    public fun query(sender:vector<u8>, contract_addr: vector<u8>, data: vector<u8>): vector<u8> acquires Account, ContractEvent {
        contract_addr = to_32bit(contract_addr);
        let contract_store = borrow_global_mut<Account>(to_address(contract_addr));
        run(sender, sender, contract_addr, contract_store.code, data, true, 0)
    }

    #[view]
    public fun get_storage_at(addr: vector<u8>, slot: vector<u8>): vector<u8> acquires Account {
        let move_address = to_address(addr);
        if(exists<Account>(move_address)) {
            let account_store = borrow_global<Account>(move_address);
            let slot_u256 = data_to_u256(slot, 0, (vector::length(&slot) as u256));
            if(table::contains(&account_store.storage, slot_u256)) {
                *table::borrow(&account_store.storage, slot_u256)
            } else {
                vector::empty<u8>()
            }
        } else {
            vector::empty<u8>()
        }
    }

    fun execute(evm_from: vector<u8>, evm_to: vector<u8>, nonce: u64, data: vector<u8>, value: u256): vector<u8> acquires Account, ContractEvent {
        let address_from = to_address(evm_from);
        let address_to = to_address(evm_to);
        create_account_if_not_exist(address_from);
        create_account_if_not_exist(address_to);
        verify_nonce(address_from, nonce);
        let account_store_to = borrow_global_mut<Account>(address_to);
        if(evm_to == DEPLOY_ADDR) {
            let evm_contract = get_contract_address(evm_from, nonce);
            let address_contract = to_address(evm_contract);
            create_account_if_not_exist(address_contract);
            create_event_if_not_exist(address_contract);
            borrow_global_mut<Account>(address_contract).is_contract = true;
            borrow_global_mut<Account>(address_contract).code = run(evm_from, evm_from, evm_contract, data, x"", false, value);
            evm_contract
        } else if(evm_to == ONE_ADDR) {
            let amount = data_to_u256(data, 36, 32);
            let to = to_address(slice(data, 100, 32));
            transfer_to_move_addr(evm_from, to, amount);
            x""
        } else {
            if(account_store_to.is_contract) {
                run(evm_from, evm_from, evm_to, account_store_to.code, data, false, value)
            } else {
                transfer_to_evm_addr(evm_from, evm_to, value);
                x""
            }
        }
    }

    fun precompile(sender: vector<u8>, value: u256, calldata: vector<u8>, readOnly: bool): vector<u8> acquires Account {
        assert!(!readOnly, CONTRACT_READ_ONLY);
        let selector = slice(calldata, 0, 4);
        assert!(selector == x"dfaea795", PRECOMPILE_SELECTOR);

        let to = to_address(slice(calldata, 4, 32));
        transfer_to_move_addr(sender, to, value);

        let signer = create_signer(to_address(sender));
        let len = to_u256(slice(calldata, 68, 32));
        execute_move_tx(&signer, to, slice(calldata, 100, len));

        vector::empty<u8>()
    }

    // This function is used to execute EVM bytecode.
    // Parameters:
    // - sender: The address of the sender.
    // - origin: The original invoker of the transaction.
    // - evm_contract_address: The EVM address of the contract.
    // - code: The EVM bytecode to be executed.
    // - data: The input data for the execution.
    // - readOnly: A boolean flag indicating whether the execution should be read-only.
    // - value: The value to be transferred during the execution.
    fun run(sender: vector<u8>, origin: vector<u8>, evm_contract_address: vector<u8>, code: vector<u8>, data: vector<u8>, readOnly: bool, value: u256): vector<u8> acquires Account, ContractEvent {
        if(evm_contract_address == PRECOMPILE_ADDR) {
            return precompile(sender, value, data, readOnly)
        };

        // Convert the EVM address to a Move resource address.
        let move_contract_address = to_address(evm_contract_address);
        // Transfer the specified value to the EVM address
        transfer_to_evm_addr(sender, evm_contract_address, value);
        // Initialize an empty stack and memory for the EVM execution.
        let stack = &mut vector::empty<u256>();
        let memory = &mut vector::empty<u8>();
        // Get the length of the bytecode.
        let len = vector::length(&code);
        // Initialize an empty vector for the runtime code.
        let runtime_code = vector::empty<u8>();
        // Initialize counters for the execution loop.
        let i = 0;
        let ret_size = 0;
        let ret_bytes = vector::empty<u8>();

        // Start the execution loop.
        while (i < len) {
            // Fetch the current opcode from the bytecode.

            let opcode = *vector::borrow(&code, i);
            // debug::print(&i);
            // debug::print(&opcode);

            // Handle each opcode according to the EVM specification.
            // The following is a simplified version of the EVM execution engine,
            // handling only a subset of all possible opcodes.
            // Each branch in this if-else chain corresponds to a specific opcode,
            // and contains the logic for executing that opcode.
            // For example, the `add` opcode pops two elements from the stack,
            // adds them together, and pushes the result back onto the stack.
            // The `mul` opcode does the same but with multiplication, and so on.
            // Some opcodes, like `sstore`, have side effects, such as modifying contract storage.
            // The `jump` and `jumpi` opcodes alter the control flow of the execution.
            // The `call`, `create`, and `create2` opcodes are used for contract interactions.
            // The `log` opcodes are used for emitting events.
            // The function returns the output data of the execution when it encounters the `stop` or `return` opcode.

            // stop
            if(opcode == 0x00) {
                ret_bytes = runtime_code;
                break
            }
            else if(opcode == 0xf3) {
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                ret_bytes = slice(*memory, pos, len);
                break
            }
                //add
            else if(opcode == 0x01) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                if(a > 0 && b >= (U256_MAX - a + 1)) {
                    vector::push_back(stack, b - (U256_MAX - a + 1));
                } else {
                    vector::push_back(stack, a + b);
                };
                i = i + 1;
            }
                //mul
            else if(opcode == 0x02) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                vector::push_back(stack, a * b);
                i = i + 1;
            }
                //sub
            else if(opcode == 0x03) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                if(a >= b) {
                    vector::push_back(stack, a - b);
                } else {
                    vector::push_back(stack, U256_MAX - b + a + 1);
                };
                i = i + 1;
            }
                //div && sdiv
            else if(opcode == 0x04 || opcode == 0x05) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                vector::push_back(stack, a / b);
                i = i + 1;
            }
                //mod && smod
            else if(opcode == 0x06 || opcode == 0x07) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                vector::push_back(stack, a % b);
                i = i + 1;
            }
                //addmod
            else if(opcode == 0x08) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                let n = vector::pop_back(stack);
                vector::push_back(stack, (a + b) % n);
                i = i + 1;
            }
                //mulmod
            else if(opcode == 0x09) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                let n = vector::pop_back(stack);
                vector::push_back(stack, (a * b) % n);
                i = i + 1;
            }
                //exp
            else if(opcode == 0x0a) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                vector::push_back(stack, power(a, b));
                i = i + 1;
            }
                //signextend
            else if(opcode == 0x0b) {
                let b = vector::pop_back(stack);
                let value = vector::pop_back(stack);
                if(b > 31) {
                    vector::push_back(stack, value);
                } else {
                    let index = ((8 * b + 7) as u8);
                    let mask = (1 << index) - 1;
                    if(((value >> index) & 1) == 0) {
                        vector::push_back(stack, value & mask);
                    } else {
                        vector::push_back(stack, value | (U256_MAX - mask));
                    };
                };
                i = i + 1;
            }
                //lt
            else if(opcode == 0x10) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                if(a < b) {
                    vector::push_back(stack, 1)
                } else {
                    vector::push_back(stack, 0)
                };
                i = i + 1;
            }
                //gt
            else if(opcode == 0x11) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                if(a > b) {
                    vector::push_back(stack, 1)
                } else {
                    vector::push_back(stack, 0)
                };
                i = i + 1;
            }
                //slt
            else if(opcode == 0x12) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                let(sg_a, num_a) = to_int256(a);
                let(sg_b, num_b) = to_int256(b);
                let value = 0;
                if((sg_a && !sg_b) || (sg_a && sg_b && num_a > num_b) || (!sg_a && !sg_b && num_a < num_b)) {
                    value = 1
                };
                vector::push_back(stack, value);
                i = i + 1;
            }
                //sgt
            else if(opcode == 0x13) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                let(sg_a, num_a) = to_int256(a);
                let(sg_b, num_b) = to_int256(b);
                let value = 0;
                if((sg_a && !sg_b) || (sg_a && sg_b && num_a < num_b) || (!sg_a && !sg_b && num_a > num_b)) {
                    value = 1
                };
                vector::push_back(stack, value);
                i = i + 1;
            }
                //eq
            else if(opcode == 0x14) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                if(a == b) {
                    vector::push_back(stack, 1);
                } else {
                    vector::push_back(stack, 0);
                };
                i = i + 1;
            }
                //and
            else if(opcode == 0x16) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                vector::push_back(stack, a & b);
                i = i + 1;
            }
                //or
            else if(opcode == 0x17) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                vector::push_back(stack, a | b);
                i = i + 1;
            }
                //xor
            else if(opcode == 0x18) {
                let a = vector::pop_back(stack);
                let b = vector::pop_back(stack);
                vector::push_back(stack, a ^ b);
                i = i + 1;
            }
                //not
            else if(opcode == 0x19) {
                // 10 1010
                // 6 0101
                let n = vector::pop_back(stack);
                vector::push_back(stack, U256_MAX - n);
                i = i + 1;
            }
                //byte
            else if(opcode == 0x1a) {
                let ith = vector::pop_back(stack);
                let x = vector::pop_back(stack);
                if(ith >= 32) {
                    vector::push_back(stack, 0);
                } else {
                    vector::push_back(stack, (x >> ((248 - ith * 8) as u8)) & 0xFF);
                };

                i = i + 1;
            }
                //shl
            else if(opcode == 0x1b) {
                let b = vector::pop_back(stack);
                let a = vector::pop_back(stack);
                if(b >= 256) {
                    vector::push_back(stack, 0);
                } else {
                    vector::push_back(stack, a << (b as u8));
                };
                i = i + 1;
            }
                //shr
            else if(opcode == 0x1c) {
                let b = vector::pop_back(stack);
                let a = vector::pop_back(stack);
                if(b >= 256) {
                    vector::push_back(stack, 0);
                } else {
                    vector::push_back(stack, a >> (b as u8));
                };

                i = i + 1;
            }
                //push0
            else if(opcode == 0x5f) {
                vector::push_back(stack, 0);
                i = i + 1;
            }
                // push1 -> push32
            else if(opcode >= 0x60 && opcode <= 0x7f)  {
                let n = ((opcode - 0x60) as u64);
                let number = data_to_u256(code, ((i + 1) as u256), ((n + 1) as u256));
                vector::push_back(stack, (number as u256));
                i = i + n + 2;
            }
                // pop
            else if(opcode == 0x50) {
                vector::pop_back(stack);
                i = i + 1
            }
                //address
            else if(opcode == 0x30) {
                vector::push_back(stack, data_to_u256(evm_contract_address, 0, 32));
                i = i + 1;
            }
                //balance
            else if(opcode == 0x31) {
                let addr = u256_to_data(vector::pop_back(stack));
                let account_store = borrow_global<Account>(to_address(addr));
                vector::push_back(stack, account_store.balance);
                i = i + 1;
            }
                //origin
            else if(opcode == 0x32) {
                let value = data_to_u256(origin, 0, 32);
                vector::push_back(stack, value);
                i = i + 1;
            }
                //caller
            else if(opcode == 0x33) {
                let value = data_to_u256(sender, 0, 32);
                vector::push_back(stack, value);
                i = i + 1;
            }
                // callvalue
            else if(opcode == 0x34) {
                vector::push_back(stack, value);
                i = i + 1;
            }
                //calldataload
            else if(opcode == 0x35) {
                let pos = vector::pop_back(stack);
                vector::push_back(stack, data_to_u256(data, pos, 32));
                i = i + 1;
                // block.
            }
                //calldatasize
            else if(opcode == 0x36) {
                vector::push_back(stack, (vector::length(&data) as u256));
                i = i + 1;
            }
                //calldatacopy
            else if(opcode == 0x37) {
                let m_pos = vector::pop_back(stack);
                let d_pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let end = d_pos + len;
                // debug::print(&utf8(b"calldatacopy"));
                // debug::print(&data);
                while (d_pos < end) {
                    // debug::print(&d_pos);
                    // debug::print(&end);
                    let bytes = if(end - d_pos >= 32) {
                        slice(data, d_pos, 32)
                    } else {
                        slice(data, d_pos, end - d_pos)
                    };
                    // debug::print(&bytes);
                    mstore(memory, m_pos, bytes);
                    d_pos = d_pos + 32;
                    m_pos = m_pos + 32;
                };
                i = i + 1
            }
                //codesize
            else if(opcode == 0x38) {
                vector::push_back(stack, (vector::length(&code) as u256));
                i = i + 1
            }
                //codecopy
            else if(opcode == 0x39) {
                let m_pos = vector::pop_back(stack);
                let d_pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let end = d_pos + len;
                runtime_code = slice(code, d_pos, len);
                while (d_pos < end) {
                    let bytes = if(end - d_pos >= 32) {
                        slice(code, d_pos, 32)
                    } else {
                        slice(code, d_pos, end - d_pos)
                    };
                    mstore(memory, m_pos, bytes);
                    d_pos = d_pos + 32;
                    m_pos = m_pos + 32;
                };
                i = i + 1
            }
                //extcodesize
            else if(opcode == 0x3b) {
                let bytes = u256_to_data(vector::pop_back(stack));
                let target_address = to_address(to_32bit(slice(bytes, 12, 20)));
                if(exists<Account>(target_address)) {
                    let code = borrow_global<Account>(target_address).code;
                    vector::push_back(stack, (vector::length(&code) as u256));
                } else {
                    vector::push_back(stack, 0);
                };

                i = i + 1;
            }
                //returndatacopy
            else if(opcode == 0x3e) {
                // mstore()
                let m_pos = vector::pop_back(stack);
                let d_pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let bytes = slice(ret_bytes, d_pos, len);
                mstore(memory, m_pos, bytes);
                i = i + 1;
            }
                //returndatasize
            else if(opcode == 0x3d) {
                vector::push_back(stack, ret_size);
                i = i + 1;
            }
                //blockhash
            else if(opcode == 0x40) {
                vector::push_back(stack, 0);
                i = i + 1;
            }
                //coinbase
            else if(opcode == 0x41) {
                vector::push_back(stack, 0);
                i = i + 1;
            }
                //timestamp
            else if(opcode == 0x42) {
                vector::push_back(stack, (now_microseconds() as u256) / 1000000);
                i = i + 1;
            }
                //number
            else if(opcode == 0x43) {
                vector::push_back(stack, (block::get_current_block_height() as u256));
                i = i + 1;
            }
                //difficulty
            else if(opcode == 0x44) {
                vector::push_back(stack, 0);
                i = i + 1;
            }
                //gaslimit
            else if(opcode == 0x45) {
                vector::push_back(stack, 30000000);
                i = i + 1;
            }
                //chainid
            else if(opcode == 0x46) {
                vector::push_back(stack, (CHAIN_ID as u256));
                i = i + 1
            }
                //self balance
            else if(opcode == 0x47) {
                let contract_store = borrow_global_mut<Account>(move_contract_address);
                vector::push_back(stack, contract_store.balance);
                i = i + 1;
            }
                // mload
            else if(opcode == 0x51) {
                let pos = vector::pop_back(stack);
                vector::push_back(stack, data_to_u256(slice(*memory, pos, 32), 0, 32));
                i = i + 1;
            }
                // mstore
            else if(opcode == 0x52) {
                let pos = vector::pop_back(stack);
                let value = vector::pop_back(stack);
                mstore(memory, pos, u256_to_data(value));
                // debug::print(memory);
                i = i + 1;

            }
                //mstore8
            else if(opcode == 0x53) {
                let pos = vector::pop_back(stack);
                let value = vector::pop_back(stack);
                *vector::borrow_mut(memory, (pos as u64)) = ((value & 0xff) as u8);
                // mstore(memory, pos, u256_to_data(value & 0xff));
                // debug::print(memory);
                i = i + 1;

            }
                // sload
            else if(opcode == 0x54) {
                let pos = vector::pop_back(stack);
                let contract_store = borrow_global_mut<Account>(move_contract_address);
                if(table::contains(&contract_store.storage, pos)) {
                    let value = *table::borrow(&mut contract_store.storage, pos);
                    vector::push_back(stack, data_to_u256(value, 0, 32));
                } else {
                    vector::push_back(stack, 0);
                };
                i = i + 1;
            }
                // sstore
            else if(opcode == 0x55) {
                assert!(!readOnly, CONTRACT_READ_ONLY);
                let contract_store = borrow_global_mut<Account>(move_contract_address);
                let pos = vector::pop_back(stack);
                let value = vector::pop_back(stack);
                table::upsert(&mut contract_store.storage, pos, u256_to_data(value));
                // debug::print(&utf8(b"sstore"));
                // debug::print(&evm_contract_address);
                // debug::print(&pos);
                // debug::print(&value);
                i = i + 1;
            }
                //dup1 -> dup16
            else if(opcode >= 0x80 && opcode <= 0x8f) {
                let size = vector::length(stack);
                let value = *vector::borrow(stack, size - ((opcode - 0x80 + 1) as u64));
                vector::push_back(stack, value);
                i = i + 1;
            }
                //swap1 -> swap16
            else if(opcode >= 0x90 && opcode <= 0x9f) {
                let size = vector::length(stack);
                vector::swap(stack, size - 1, size - ((opcode - 0x90 + 2) as u64));
                i = i + 1;
            }
                //iszero
            else if(opcode == 0x15) {
                let value = vector::pop_back(stack);
                if(value == 0) {
                    vector::push_back(stack, 1)
                } else {
                    vector::push_back(stack, 0)
                };
                i = i + 1;
            }
                //jump
            else if(opcode == 0x56) {
                let dest = vector::pop_back(stack);
                i = (dest as u64) + 1
            }
                //jumpi
            else if(opcode == 0x57) {
                let dest = vector::pop_back(stack);
                let condition = vector::pop_back(stack);
                if(condition > 0) {
                    i = (dest as u64) + 1
                } else {
                    i = i + 1
                }
            }
                //gas
            else if(opcode == 0x5a) {
                vector::push_back(stack, 30000000);
                i = i + 1
            }
                //jump dest (no action, continue execution)
            else if(opcode == 0x5b) {
                i = i + 1
            }
                //sha3
            else if(opcode == 0x20) {
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let bytes = slice(*memory, pos, len);
                // debug::print(&utf8(b"sha3"));
                // debug::print(&bytes);
                let value = data_to_u256(keccak256(bytes), 0, 32);
                // debug::print(&value);
                vector::push_back(stack, value);
                i = i + 1
            }
                //call 0xf1 static call 0xfa delegate call 0xf4
            else if(opcode == 0xf1 || opcode == 0xfa || opcode == 0xf4) {
                let readOnly = if (opcode == 0xfa) true else false;
                let _gas = vector::pop_back(stack);
                let evm_dest_addr = to_32bit(u256_to_data(vector::pop_back(stack)));
                let move_dest_addr = to_address(evm_dest_addr);
                let msg_value = if (opcode == 0xf1) vector::pop_back(stack) else 0;
                let m_pos = vector::pop_back(stack);
                let m_len = vector::pop_back(stack);
                let ret_pos = vector::pop_back(stack);
                let ret_len = vector::pop_back(stack);


                // debug::print(&utf8(b"call 222"));
                // debug::print(&opcode);
                // debug::print(&dest_addr);
                if (evm_dest_addr == PRECOMPILE_ADDR || (exists<Account>(move_dest_addr) && borrow_global_mut<Account>(move_dest_addr).is_contract)) {
                    let ret_end = ret_len + ret_pos;
                    let params = slice(*memory, m_pos, m_len);
                    let account_store_dest = borrow_global_mut<Account>(move_dest_addr);

                    let target = if (opcode == 0xf4) evm_contract_address else evm_dest_addr;
                    let from = if (opcode == 0xf4) sender else evm_contract_address;
                    // debug::print(&utf8(b"call"));
                    // debug::print(&params);
                    // if(opcode == 0xf4) {
                    //     debug::print(&utf8(b"delegate call"));
                    //     debug::print(&sender);
                    //     debug::print(&target);
                    // };
                    ret_bytes = run(from, sender, target, account_store_dest.code, params, readOnly, msg_value);
                    ret_size = (vector::length(&ret_bytes) as u256);
                    let index = 0;
                    // if(opcode == 0xf4) {
                    //     storage = simple_map::borrow_mut<vector<u8>, T>(&mut global.contracts, &contract_addr).storage;
                    // };
                    while (ret_pos < ret_end) {
                        let bytes = if (ret_end - ret_pos >= 32) {
                            slice(ret_bytes, index, 32)
                        } else {
                            slice(ret_bytes, index, ret_end - ret_pos)
                        };
                        mstore(memory, ret_pos, bytes);
                        ret_pos = ret_pos + 32;
                        index = index + 32;
                    };
                    vector::push_back(stack, 1);
                } else {
                    if (opcode == 0xfa) {
                        vector::push_back(stack, 0);
                    } else {
                        transfer_to_evm_addr(evm_contract_address, evm_dest_addr, msg_value);
                    }
                };
                // debug::print(&opcode);
                i = i + 1
            }
                //create
            else if(opcode == 0xf0) {
                assert!(!readOnly, CONTRACT_READ_ONLY);
                let msg_value = vector::pop_back(stack);
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let new_codes = slice(*memory, pos, len);
                let contract_store = borrow_global_mut<Account>(move_contract_address);
                let nonce = contract_store.nonce;
                // must be 20 bytes

                let new_evm_contract_addr = get_contract_address(evm_contract_address, nonce);
                debug::print(&utf8(b"create start"));
                debug::print(&new_evm_contract_addr);
                let new_move_contract_addr = to_address(new_evm_contract_addr);
                contract_store.nonce = contract_store.nonce + 1;

                debug::print(&exists<Account>(new_move_contract_addr));
                assert!(!exist_contract(new_move_contract_addr), CREATE_CONTRACT_DEPLOYED);
                create_account_if_not_exist(new_move_contract_addr);
                create_event_if_not_exist(new_move_contract_addr);

                // let new_contract_store = borrow_global_mut<Account>(new_move_contract_addr);
                borrow_global_mut<Account>(move_contract_address).nonce = 1;
                borrow_global_mut<Account>(move_contract_address).is_contract = true;
                borrow_global_mut<Account>(move_contract_address).code = run(evm_contract_address, sender, new_evm_contract_addr, new_codes, x"", false, msg_value);

                debug::print(&utf8(b"create end"));
                ret_size = 32;
                ret_bytes = new_evm_contract_addr;
                vector::push_back(stack, data_to_u256(new_evm_contract_addr, 0, 32));
                i = i + 1
            }
                //create2
            else if(opcode == 0xf5) {
                if(readOnly) {
                    assert!(false, CONTRACT_READ_ONLY);
                };
                let msg_value = vector::pop_back(stack);
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let salt = u256_to_data(vector::pop_back(stack));
                let new_codes = slice(*memory, pos, len);
                let p = vector::empty<u8>();
                // let contract_store = ;
                vector::append(&mut p, x"ff");
                // must be 20 bytes
                vector::append(&mut p, slice(evm_contract_address, 12, 20));
                vector::append(&mut p, salt);
                vector::append(&mut p, keccak256(new_codes));
                // vector::append(&mut p, x"949a457935c25c9ba74fed34a89f32bee4b242d0d2f51e0c9d4020b45788a1d1");
                let new_evm_contract_addr = to_32bit(slice(keccak256(p), 12, 20));
                let new_move_contract_addr = to_address(new_evm_contract_addr);
                debug::print(&utf8(b"create2 start"));
                debug::print(&p);
                debug::print(&new_codes);
                debug::print(&keccak256(new_codes));
                debug::print(&new_evm_contract_addr);
                debug::print(&exists<Account>(new_move_contract_addr));
                assert!(!exist_contract(new_move_contract_addr), CREATE2_CONTRACT_DEPLOYED);
                create_account_if_not_exist(new_move_contract_addr);
                create_event_if_not_exist(new_move_contract_addr);

                // debug::print(&p);
                // debug::print(&new_codes);
                // debug::print(&new_contract_addr);
                borrow_global_mut<Account>(move_contract_address).nonce = borrow_global_mut<Account>(move_contract_address).nonce + 1;
                // let new_contract_store = borrow_global_mut<Account>(new_move_contract_addr);
                borrow_global_mut<Account>(new_move_contract_addr).nonce = 1;
                borrow_global_mut<Account>(new_move_contract_addr).is_contract = true;
                borrow_global_mut<Account>(new_move_contract_addr).code = run(evm_contract_address, sender, new_evm_contract_addr, new_codes, x"", false, msg_value);
                // new_contract_store.code = code;
                ret_size = 32;
                ret_bytes = new_evm_contract_addr;
                vector::push_back(stack, data_to_u256(new_evm_contract_addr,0, 32));
                i = i + 1
            }
                //revert
            else if(opcode == 0xfd) {
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let bytes = slice(*memory, pos, len);
                debug::print(&bytes);
                // debug::print(&pos);
                // debug::print(&len);
                // debug::print(memory);
                i = i + 1;
                assert!(false, (opcode as u64));
            }
                //log0
            else if(opcode == 0xa0) {
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let data = slice(*memory, pos, len);
                let event_store = borrow_global_mut<ContractEvent>(move_contract_address);
                event::emit_event<Log0Event>(
                    &mut event_store.log0Event,
                    Log0Event{
                        contract: evm_contract_address,
                        data,
                    },
                );
                i = i + 1
            }
                //log1
            else if(opcode == 0xa1) {
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let data = slice(*memory, pos, len);
                let topic0 = u256_to_data(vector::pop_back(stack));
                let event_store = borrow_global_mut<ContractEvent>(move_contract_address);
                event::emit_event<Log1Event>(
                    &mut event_store.log1Event,
                    Log1Event{
                        contract: evm_contract_address,
                        data,
                        topic0,
                    },
                );
                i = i + 1
            }
                //log2
            else if(opcode == 0xa2) {
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let data = slice(*memory, pos, len);
                let topic0 = u256_to_data(vector::pop_back(stack));
                let topic1 = u256_to_data(vector::pop_back(stack));
                let event_store = borrow_global_mut<ContractEvent>(move_contract_address);
                event::emit_event<Log2Event>(
                    &mut event_store.log2Event,
                    Log2Event{
                        contract: evm_contract_address,
                        data,
                        topic0,
                        topic1
                    },
                );
                i = i + 1
            }
                //log3
            else if(opcode == 0xa3) {
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let data = slice(*memory, pos, len);
                let topic0 = u256_to_data(vector::pop_back(stack));
                let topic1 = u256_to_data(vector::pop_back(stack));
                let topic2 = u256_to_data(vector::pop_back(stack));
                let event_store = borrow_global_mut<ContractEvent>(move_contract_address);
                event::emit_event<Log3Event>(
                    &mut event_store.log3Event,
                    Log3Event{
                        contract: evm_contract_address,
                        data,
                        topic0,
                        topic1,
                        topic2
                    },
                );
                i = i + 1
            }
                //log4
            else if(opcode == 0xa4) {
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let data = slice(*memory, pos, len);
                let topic0 = u256_to_data(vector::pop_back(stack));
                let topic1 = u256_to_data(vector::pop_back(stack));
                let topic2 = u256_to_data(vector::pop_back(stack));
                let topic3 = u256_to_data(vector::pop_back(stack));
                let event_store = borrow_global_mut<ContractEvent>(move_contract_address);
                event::emit_event<Log4Event>(
                    &mut event_store.log4Event,
                    Log4Event{
                        contract: evm_contract_address,
                        data,
                        topic0,
                        topic1,
                        topic2,
                        topic3
                    },
                );
                i = i + 1
            }
            else {
                assert!(false, (opcode as u64));
            };
            // debug::print(stack);
            // debug::print(&vector::length(stack));
        };
        // simple_map::borrow_mut<vector<u8>, T>(&mut global.contracts, &contract_addr).storage = storage;
        ret_bytes
    }

    fun exist_contract(addr: address): bool acquires Account {
        exists<Account>(addr) && (vector::length(&borrow_global<Account>(addr).code) > 0)
    }

    fun add_balance(addr: address, amount: u256) acquires Account {
        create_account_if_not_exist(addr);
        if(amount > 0) {
            let account_store = borrow_global_mut<Account>(addr);
            account_store.balance = account_store.balance + amount;
        }
    }

    fun transfer_from_move_addr(signer: &signer, evm_to: vector<u8>, amount: u256) acquires Account {
        if(amount > 0) {
            let move_to = to_address(evm_to);
            create_account_if_not_exist(move_to);
            coin::transfer<AptosCoin>(signer, move_to, ((amount / CONVERT_BASE)  as u64));

            let account_store_to = borrow_global_mut<Account>(move_to);
            account_store_to.balance = account_store_to.balance + amount;
        }
    }

    fun transfer_to_evm_addr(evm_from: vector<u8>, evm_to: vector<u8>, amount: u256) acquires Account {
        if(amount > 0) {
            let move_from = to_address(evm_from);
            let move_to = to_address(evm_to);
            let account_store_from = borrow_global_mut<Account>(move_from);
            assert!(account_store_from.balance >= amount, INSUFFIENT_BALANCE);
            account_store_from.balance = account_store_from.balance - amount;

            let account_store_to = borrow_global_mut<Account>(move_to);
            account_store_to.balance = account_store_to.balance + amount;

            let signer = create_signer(move_from);
            coin::transfer<AptosCoin>(&signer, move_to, ((amount / CONVERT_BASE)  as u64));
        }
    }

    fun transfer_to_move_addr(evm_from: vector<u8>, move_to: address, amount: u256) acquires Account {
        if(amount > 0) {
            let move_from = to_address(evm_from);
            let account_store_from = borrow_global_mut<Account>(move_from);
            assert!(account_store_from.balance >= amount, INSUFFIENT_BALANCE);
            account_store_from.balance = account_store_from.balance - amount;

            let signer = create_signer(move_from);
            coin::transfer<AptosCoin>(&signer, move_to, ((amount / CONVERT_BASE)  as u64));
        }
    }

    fun create_event_if_not_exist(addr: address) {
        if(!exists<ContractEvent>(addr)) {
            let signer = create_signer(addr);
            move_to(&signer, ContractEvent {
                log0Event: new_event_handle<Log0Event>(&signer),
                log1Event: new_event_handle<Log1Event>(&signer),
                log2Event: new_event_handle<Log2Event>(&signer),
                log3Event: new_event_handle<Log3Event>(&signer),
                log4Event: new_event_handle<Log4Event>(&signer),
            })
        }
    }

    fun create_account_if_not_exist(addr: address) {
        if(!exists<Account>(addr)) {
            let signer = create_signer(addr);
            if(!exists_at(addr)) {
                create_account(addr);
                coin::register<AptosCoin>(&signer);
            };

            move_to(&signer, Account {
                code: vector::empty(),
                storage: table::new<u256, vector<u8>>(),
                balance: 0,
                is_contract: false,
                nonce: 0
            })
        };
    }

    fun verify_nonce(addr: address, nonce: u64) acquires Account {
        let coin_store_from = borrow_global_mut<Account>(addr);
        assert!(coin_store_from.nonce == nonce, NONCE);
        coin_store_from.nonce = coin_store_from.nonce + 1;
    }

    fun verify_signature(from: vector<u8>, message_hash: vector<u8>, r: vector<u8>, s: vector<u8>, v: u64) {
        let input_bytes = r;
        vector::append(&mut input_bytes, s);
        let signature = ecdsa_signature_from_bytes(input_bytes);
        let recovery_id = if(v > 28) ((v - (CHAIN_ID * 2) - 35) as u8) else ((v - 27) as u8);
        let pk_recover = ecdsa_recover(message_hash, recovery_id, &signature);
        let pk = keccak256(ecdsa_raw_public_key_to_bytes(borrow(&pk_recover)));
        debug::print(&slice(pk, 12, 20));
        assert!(slice(pk, 12, 20) == from, SIGNATURE);
    }

    #[test(owner_2 = @0x124)]
    fun test_precompile(owner_2: &signer) acquires Account {
        let owner_2_addr = address_of(owner_2);
        let framework_signer = &create_signer(@0x1);
        features::change_feature_flags(
            framework_signer, vector[features::get_multisig_accounts_feature()], vector[]);
        timestamp::set_time_has_started_for_testing(framework_signer);
        chain_id::initialize_for_test(framework_signer, 1);
        let sender = to_32bit(x"054ecb78d0276cf182514211d0c21fe46590b654");

        let addr = to_address(sender);
        let owner = create_account_for_test(addr);
        let multisig_account = get_next_multisig_account_address(addr);
        debug::print(&multisig_account);

        create_with_owners(&owner, vector[owner_2_addr], 2, vector[], vector[]);
        create_transaction(owner_2, multisig_account, vector[1, 2, 3]);
        debug::print(&can_be_executed(multisig_account, 1));

        let calldata = x"dfaea79500000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000006410d6791e69a62494f12ebcf5de820e0f70dfe6e9d9f67e979b7da1a34be4bb2d785973ba0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000";
        precompile(sender, 0, calldata, false);

        debug::print(&can_be_executed(multisig_account, 1));
    }

    #[test]
    fun test_simple_deploy() acquires Account, ContractEvent {
        let sender = to_32bit(x"054ecb78d0276cf182514211d0c21fe46590b654");
        create_account_if_not_exist(to_address(sender));
        let weth_bytecode = x"60c0604052600d60808190526c2bb930b83832b21022ba3432b960991b60a090815261002e916000919061007a565b50604080518082019091526004808252630ae8aa8960e31b602090920191825261005a9160019161007a565b506002805460ff1916601217905534801561007457600080fd5b50610115565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100bb57805160ff19168380011785556100e8565b828001600101855582156100e8579182015b828111156100e85782518255916020019190600101906100cd565b506100f49291506100f8565b5090565b61011291905b808211156100f457600081556001016100fe565b90565b61074f806101246000396000f3fe60806040526004361061009c5760003560e01c8063313ce56711610064578063313ce5671461020e57806370a082311461023957806395d89b411461026c578063a9059cbb14610281578063d0e30db0146102ba578063dd62ed3e146102c25761009c565b806306fdde03146100a1578063095ea7b31461012b57806318160ddd1461017857806323b872dd1461019f5780632e1a7d4d146101e2575b600080fd5b3480156100ad57600080fd5b506100b66102fd565b6040805160208082528351818301528351919283929083019185019080838360005b838110156100f05781810151838201526020016100d8565b50505050905090810190601f16801561011d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561013757600080fd5b506101646004803603604081101561014e57600080fd5b506001600160a01b03813516906020013561038b565b604080519115158252519081900360200190f35b34801561018457600080fd5b5061018d6103f1565b60408051918252519081900360200190f35b3480156101ab57600080fd5b50610164600480360360608110156101c257600080fd5b506001600160a01b038135811691602081013590911690604001356103f5565b3480156101ee57600080fd5b5061020c6004803603602081101561020557600080fd5b503561056d565b005b34801561021a57600080fd5b50610223610624565b6040805160ff9092168252519081900360200190f35b34801561024557600080fd5b5061018d6004803603602081101561025c57600080fd5b50356001600160a01b031661062d565b34801561027857600080fd5b506100b661063f565b34801561028d57600080fd5b50610164600480360360408110156102a457600080fd5b506001600160a01b038135169060200135610699565b61020c6106ad565b3480156102ce57600080fd5b5061018d600480360360408110156102e557600080fd5b506001600160a01b03813581169160200135166106fc565b6000805460408051602060026001851615610100026000190190941693909304601f810184900484028201840190925281815292918301828280156103835780601f1061035857610100808354040283529160200191610383565b820191906000526020600020905b81548152906001019060200180831161036657829003601f168201915b505050505081565b3360008181526004602090815260408083206001600160a01b038716808552908352818420869055815186815291519394909390927f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925928290030190a350600192915050565b4790565b6001600160a01b03831660009081526003602052604081205482111561043c576040805162461bcd60e51b8152602060048201526000602482015290519081900360640190fd5b6001600160a01b038416331480159061047a57506001600160a01b038416600090815260046020908152604080832033845290915290205460001914155b156104fc576001600160a01b03841660009081526004602090815260408083203384529091529020548211156104d1576040805162461bcd60e51b8152602060048201526000602482015290519081900360640190fd5b6001600160a01b03841660009081526004602090815260408083203384529091529020805483900390555b6001600160a01b03808516600081815260036020908152604080832080548890039055938716808352918490208054870190558351868152935191937fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef929081900390910190a35060019392505050565b336000908152600360205260409020548111156105ab576040805162461bcd60e51b8152602060048201526000602482015290519081900360640190fd5b33600081815260036020526040808220805485900390555183156108fc0291849190818181858888f193505050501580156105ea573d6000803e3d6000fd5b5060408051828152905133917f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65919081900360200190a250565b60025460ff1681565b60036020526000908152604090205481565b60018054604080516020600284861615610100026000190190941693909304601f810184900484028201840190925281815292918301828280156103835780601f1061035857610100808354040283529160200191610383565b60006106a63384846103f5565b9392505050565b33600081815260036020908152604091829020805434908101909155825190815291517fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c9281900390910190a2565b60046020908152600092835260408084209091529082529020548156fea2646970667358221220da9c3a111ff307bcc21a489b63cc555d04d91b6d0ff23237180b67a42b605beb64736f6c63430006060033";
        let weth_addr = execute(sender, DEPLOY_ADDR, 0, weth_bytecode, 0);
        debug::print(&weth_addr);
    }

    #[test]
    fun test_simple_move_tx() acquires Account, ContractEvent {
        let sender = create_account_for_test(to_address(to_32bit(x"054ecb78d0276cf182514211d0c21fe46590b654")));

        let weth_bytecode = x"60c0604052600d60808190526c2bb930b83832b21022ba3432b960991b60a090815261002e916000919061007a565b50604080518082019091526004808252630ae8aa8960e31b602090920191825261005a9160019161007a565b506002805460ff1916601217905534801561007457600080fd5b50610115565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f106100bb57805160ff19168380011785556100e8565b828001600101855582156100e8579182015b828111156100e85782518255916020019190600101906100cd565b506100f49291506100f8565b5090565b61011291905b808211156100f457600081556001016100fe565b90565b61074f806101246000396000f3fe60806040526004361061009c5760003560e01c8063313ce56711610064578063313ce5671461020e57806370a082311461023957806395d89b411461026c578063a9059cbb14610281578063d0e30db0146102ba578063dd62ed3e146102c25761009c565b806306fdde03146100a1578063095ea7b31461012b57806318160ddd1461017857806323b872dd1461019f5780632e1a7d4d146101e2575b600080fd5b3480156100ad57600080fd5b506100b66102fd565b6040805160208082528351818301528351919283929083019185019080838360005b838110156100f05781810151838201526020016100d8565b50505050905090810190601f16801561011d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b34801561013757600080fd5b506101646004803603604081101561014e57600080fd5b506001600160a01b03813516906020013561038b565b604080519115158252519081900360200190f35b34801561018457600080fd5b5061018d6103f1565b60408051918252519081900360200190f35b3480156101ab57600080fd5b50610164600480360360608110156101c257600080fd5b506001600160a01b038135811691602081013590911690604001356103f5565b3480156101ee57600080fd5b5061020c6004803603602081101561020557600080fd5b503561056d565b005b34801561021a57600080fd5b50610223610624565b6040805160ff9092168252519081900360200190f35b34801561024557600080fd5b5061018d6004803603602081101561025c57600080fd5b50356001600160a01b031661062d565b34801561027857600080fd5b506100b661063f565b34801561028d57600080fd5b50610164600480360360408110156102a457600080fd5b506001600160a01b038135169060200135610699565b61020c6106ad565b3480156102ce57600080fd5b5061018d600480360360408110156102e557600080fd5b506001600160a01b03813581169160200135166106fc565b6000805460408051602060026001851615610100026000190190941693909304601f810184900484028201840190925281815292918301828280156103835780601f1061035857610100808354040283529160200191610383565b820191906000526020600020905b81548152906001019060200180831161036657829003601f168201915b505050505081565b3360008181526004602090815260408083206001600160a01b038716808552908352818420869055815186815291519394909390927f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925928290030190a350600192915050565b4790565b6001600160a01b03831660009081526003602052604081205482111561043c576040805162461bcd60e51b8152602060048201526000602482015290519081900360640190fd5b6001600160a01b038416331480159061047a57506001600160a01b038416600090815260046020908152604080832033845290915290205460001914155b156104fc576001600160a01b03841660009081526004602090815260408083203384529091529020548211156104d1576040805162461bcd60e51b8152602060048201526000602482015290519081900360640190fd5b6001600160a01b03841660009081526004602090815260408083203384529091529020805483900390555b6001600160a01b03808516600081815260036020908152604080832080548890039055938716808352918490208054870190558351868152935191937fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef929081900390910190a35060019392505050565b336000908152600360205260409020548111156105ab576040805162461bcd60e51b8152602060048201526000602482015290519081900360640190fd5b33600081815260036020526040808220805485900390555183156108fc0291849190818181858888f193505050501580156105ea573d6000803e3d6000fd5b5060408051828152905133917f7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65919081900360200190a250565b60025460ff1681565b60036020526000908152604090205481565b60018054604080516020600284861615610100026000190190941693909304601f810184900484028201840190925281815292918301828280156103835780601f1061035857610100808354040283529160200191610383565b60006106a63384846103f5565b9392505050565b33600081815260036020908152604091829020805434908101909155825190815291517fe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c9281900390910190a2565b60046020908152600092835260408084209091529082529020548156fea2646970667358221220da9c3a111ff307bcc21a489b63cc555d04d91b6d0ff23237180b67a42b605beb64736f6c63430006060033";
        send_move_tx_to_evm(&sender, 0, DEPLOY_ADDR, u256_to_data(0), weth_bytecode, 1);
        // let weth_addr = execute(sender, DEPLOY_ADDR, 0, weth_bytecode, 0);
        // debug::print(&weth_addr);
    }

    #[test(evm = @0x2)]
    fun test_deposit_withdraw() acquires Account {
        let signer = x"914d7fec6aac8cd542e72bca78b30650d45643d7";
        debug::print(&get_contract_address(to_32bit(signer), 0));
        let evm_addr = to_bytes(&@0x35756ba5b95c593377854ae0d8d8a9f1251c3cb42046539b82bb1ce39e264acf);
        let move_addr = to_address(evm_addr);
        debug::print(&evm_addr);
        debug::print(&move_addr);

        debug::print(&to_bytes(&@aptos_framework));
        debug::print(&get_contract_address(to_32bit(x"892a2b7cF919760e148A0d33C1eb0f44D3b383f8"), 8));

        // let sender = x"054ecb78d0276cf182514211d0c21fe46590b654";
        let sender = x"edd3bce148f5acffd4ae7589d12cf51f7e4788c6";
        let evm = account::create_account_for_test(@0x1);
        let (burn_cap, freeze_cap, mint_cap) = coin::initialize<AptosCoin>(
            &evm,
            string::utf8(b"APT"),
            string::utf8(b"APT"),
            8,
            false,
        );

        let to = account::create_account_for_test(@0xc5cb1f1ce6951226e9c46ce8d42eda1ac9774a0fef91e2910939119ef0c95568);
        let coins = coin::mint<AptosCoin>(1000000000000, &mint_cap);
        coin::register<AptosCoin>(&to);
        coin::register<AptosCoin>(&evm);
        coin::deposit(@aptos_framework, coins);

        deposit(&evm, sender, u256_to_data(10000000000000000000));

        // let tx = x"f8eb8085e8d4a5100082520894a4cd3b0eb6e5ab5d8ce4065bccd70040adab1f0080b884c7012626000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000027100000000000000000000000000000000000000000000000000000000000000020c5cb1f1ce6951226e9c46ce8d42eda1ac9774a0fef91e2910939119ef0c955688202c3a0bdbf42ff5f141f989d3b546f8a8514857d036cfccd8e0c3e56d4644e08e40ea1a03908d910179e0e1b6b4ea43b4cbdcfc21f9fb74cf3cca3adde058a062a8bebf6";
        // send_tx(&evm, sender, tx, 0, 1);

        debug::print(&coin::balance<AptosCoin>(@aptos_framework));
        debug::print(&coin::balance<AptosCoin>(@0xc5cb1f1ce6951226e9c46ce8d42eda1ac9774a0fef91e2910939119ef0c95568));
        // let coin_store_account = borrow_global<Account>(@aptos_framework);
        // debug::print(&coin_store_account.balance);

        let sender = x"8db97c7cece249c2b98bdc0226cc4c2a57bf52fc";
        deposit(&evm, sender, u256_to_data(1000000000000000000));
        // let data = x"608060405234801561001057600080fd5b5060f78061001f6000396000f3fe6080604052348015600f57600080fd5b5060043610603c5760003560e01c80633fb5c1cb1460415780638381f58a146053578063d09de08a14606d575b600080fd5b6051604c3660046083565b600055565b005b605b60005481565b60405190815260200160405180910390f35b6051600080549080607c83609b565b9190505550565b600060208284031215609457600080fd5b5035919050565b60006001820160ba57634e487b7160e01b600052601160045260246000fd5b506001019056fea2646970667358221220b7acd98dc008db06cadaea72991d3736d8dd08fbbf4bde9f69be2723a32b9be864736f6c63430008150033";
        // estimate_tx_gas(sender, data, u256_to_data(21000), u256_to_data(0), 1);
        // deposit(&evm, sender, u256_to_data(1000000000000000000));
        // let coin_store_account = borrow_global<Account>(create_resource_address(&@aptos_framework, to_32bit(sender)));
        // debug::print(&coin_store_account.balance);
        // let sender = x"749cf96d9291795a74572ef7089e34ee650dac8c";
        // let tx = x"f9605a81d086015d3ef79800830f42408080b96003615fdd610026600b82828239805160001a60731461001957fe5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600436106100355760003560e01c8063c49917d71461003a575b600080fd5b61004d610048366004613f08565b610063565b60405161005a919061464a565b60405180910390f35b6060600061007e83610079856101800151610170565b6103d1565b905060006100b2610092856060015161048c565b61009f866080015161048c565b6100ad876101a00151610644565b61065a565b905060006101006100c6866000015161068c565b6100d3876080015161048c565b6100e08860200151610644565b6100ed8960400151610644565b6100fb8a6101800151610170565b610767565b905060006101156101108761079d565b6109d8565b90506101458484848460405160200161013194939291906142c5565b6040516020818303038152906040526109d8565b6040516020016101559190614605565b6040516020818303038152906040529450505050505b919050565b606062ffffff82166101b6575060408051808201909152600281527f3025000000000000000000000000000000000000000000000000000000000000602082015261016b565b816000805b62ffffff8316156102065760ff8116156101d7576001016101f0565b600a62ffffff84160662ffffff166000146101f0576001015b600190910190600a62ffffff84160492506101bb565b61020e613e02565b60006005841061030357600060046102298660ff8716610b5d565b1015610236576001610239565b60005b60ff908116915061024d9085166001610b5d565b610258866005610b5d565b106102845761027f61026e60ff86166001610b5d565b610279876005610b5d565b90610b5d565b610287565b60005b60ff8516608085018190529092506102a6906001906102799085610bba565b60ff90811660a085015260808401516102cd9183916102c791166001610b5d565b90610bba565b60ff90811660408501526102f59082906102c7906102ee9088166001610bba565b8590610bba565b60ff16602084015250610373565b61030e600585610b5d565b60026080840181905290915061032c90600190610279908490610bba565b60ff90811660a084015261034e906103479085166002610bba565b8290610bba565b60ff1660208301819052610363906002610b5d565b60ff166040830152600160c08301525b6103926103838560ff8616610b5d565b62ffffff891690600a0a610c14565b8252600160e0830152600484116103aa5760006103b5565b6103b5846004610b5d565b60ff1660608301526103c682610c7b565b979650505050505050565b6060816103e1846060015161048c565b6103ee856080015161048c565b6104278660e00151156104065786610120015161040d565b8661010001515b8761016001518860c001518960a001518a60e00151610ea7565b6104608760e001511561043f57876101000151610446565b8761012001515b8861016001518960c001518a60a001518b60e00151610ea7565b6040516020016104749594939291906143ec565b60405160208183030381529060405290505b92915050565b6060816000805b82518160ff1610156104f057828160ff16815181106104ae57fe5b6020910101517fff0000000000000000000000000000000000000000000000000000000000000016601160f91b14156104e8576001909101905b600101610493565b5060ff81161561063c5760008160ff1683510167ffffffffffffffff8111801561051957600080fd5b506040519080825280601f01601f191660200182016040528015610544576020820181803683370190505b5090506000805b84518160ff16101561062f57848160ff168151811061056657fe5b6020910101517fff0000000000000000000000000000000000000000000000000000000000000016601160f91b14156105e4577f5c000000000000000000000000000000000000000000000000000000000000008383806001019450815181106105cc57fe5b60200101906001600160f81b031916908160001a9053505b848160ff16815181106105f357fe5b602001015160f81c60f81b83838060010194508151811061061057fe5b60200101906001600160f81b031916908160001a90535060010161054b565b508194505050505061016b565b509192915050565b60606104866001600160a01b0383166014610fd1565b6060838383866040516020016106739493929190614179565b60405160208183030381529060405290505b9392505050565b6060816106b157506040805180820190915260018152600360fc1b602082015261016b565b8160005b81156106c957600101600a820491506106b5565b60008167ffffffffffffffff811180156106e257600080fd5b506040519080825280601f01601f19166020018201604052801561070d576020820181803683370190505b50859350905060001982015b831561075e57600a840660300160f81b8282806001900393508151811061073c57fe5b60200101906001600160f81b031916908160001a905350600a84049350610719565b50949350505050565b606083858484896040516020016107829594939291906144ed565b60405160208183030381529060405290505b95945050505050565b60606000604051806102a001604052806107ba8560200151610644565b81526020016107cc8560400151610644565b8152602001846101a001516001600160a01b031681526020018460600151815260200184608001518152602001610807856101800151610170565b815260200184610100015160020b815260200184610120015160020b815260200184610160015160020b8152602001610850856101000151866101200151876101400151611159565b60000b81526020018460000151815260200161087a85602001516001600160a01b03166088611190565b815260200161089785604001516001600160a01b03166088611190565b81526020016108b485602001516001600160a01b03166000611190565b81526020016108d185604001516001600160a01b03166000611190565b81526020016109046108f686602001516001600160a01b03166010886000015161119f565b600060ff60106101126111bf565b815260200161093761092986604001516001600160a01b03166010886000015161119f565b600060ff60646101e46111bf565b815260200161095c6108f686602001516001600160a01b03166020886000015161119f565b815260200161098161092986604001516001600160a01b03166020886000015161119f565b81526020016109a66108f686602001516001600160a01b03166030886000015161119f565b81526020016109cb61092986604001516001600160a01b03166030886000015161119f565b9052905061068581611207565b60608151600014156109f9575060408051602081019091526000815261016b565b600060405180606001604052806040815260200161526b60409139905060006003845160020181610a2657fe5b04600402905060008160200167ffffffffffffffff81118015610a4857600080fd5b506040519080825280601f01601f191660200182016040528015610a73576020820181803683370190505b509050818152600183018586518101602084015b81831015610ae15760039283018051603f601282901c811687015160f890811b8552600c83901c8216880151811b6001860152600683901c8216880151811b60028601529116860151901b93820193909352600401610a87565b600389510660018114610afb5760028114610b2757610b4f565b7f3d3d000000000000000000000000000000000000000000000000000000000000600119830152610b4f565b7f3d000000000000000000000000000000000000000000000000000000000000006000198301525b509398975050505050505050565b600082821115610bb4576040805162461bcd60e51b815260206004820152601e60248201527f536166654d6174683a207375627472616374696f6e206f766572666c6f770000604482015290519081900360640190fd5b50900390565b600082820183811015610685576040805162461bcd60e51b815260206004820152601b60248201527f536166654d6174683a206164646974696f6e206f766572666c6f770000000000604482015290519081900360640190fd5b6000808211610c6a576040805162461bcd60e51b815260206004820152601a60248201527f536166654d6174683a206469766973696f6e206279207a65726f000000000000604482015290519081900360640190fd5b818381610c7357fe5b049392505050565b60606000826020015160ff1667ffffffffffffffff81118015610c9d57600080fd5b506040519080825280601f01601f191660200182016040528015610cc8576020820181803683370190505b5090508260e0015115610d1e577f250000000000000000000000000000000000000000000000000000000000000081600183510381518110610d0657fe5b60200101906001600160f81b031916908160001a9053505b8260c0015115610d7b57600360fc1b81600081518110610d3a57fe5b60200101906001600160f81b031916908160001a905350601760f91b81600181518110610d6357fe5b60200101906001600160f81b031916908160001a9053505b608083015160ff165b60a0840151610d979060ff166001610bba565b811015610dce57603060f81b828281518110610daf57fe5b60200101906001600160f81b031916908160001a905350600101610d84565b505b825115610486576000836060015160ff16118015610dfb5750826060015160ff16836040015160ff16145b15610e3e5760408301805160ff600019820181169092528251601760f91b92849216908110610e2657fe5b60200101906001600160f81b031916908160001a9053505b8251610e5090603090600a9006610bba565b60f81b818460400180518091906001900360ff1660ff1681525060ff1681518110610e7757fe5b60200101906001600160f81b031916908160001a905350600a8360000181815181610e9e57fe5b04905250610dd0565b606084600281900b620d89e71981610ebb57fe5b050260020b8660020b1415610f15578115610ef1576040518060400160405280600381526020016209a82b60eb1b815250610f0e565b6040518060400160405280600381526020016226a4a760e91b8152505b9050610794565b84600281900b620d89e881610f2657fe5b050260020b8660020b1415610f7c578115610f5c576040518060400160405280600381526020016226a4a760e91b815250610f0e565b5060408051808201909152600381526209a82b60eb1b6020820152610794565b6000610f8787611496565b90508215610fbe57610fbb78010000000000000000000000000000000000000000000000006001600160a01b038316610c14565b90505b610fc98186866117e4565b915050610794565b606060008260020260020167ffffffffffffffff81118015610ff257600080fd5b506040519080825280601f01601f19166020018201604052801561101d576020820181803683370190505b509050600360fc1b8160008151811061103257fe5b60200101906001600160f81b031916908160001a9053507f78000000000000000000000000000000000000000000000000000000000000008160018151811061107757fe5b60200101906001600160f81b031916908160001a905350600160028402015b6001811115611105577f303132333435363738396162636465660000000000000000000000000000000085600f16601081106110ce57fe5b1a60f81b8282815181106110de57fe5b60200101906001600160f81b031916908160001a90535060049490941c9360001901611096565b508315610685576040805162461bcd60e51b815260206004820181905260248201527f537472696e67733a20686578206c656e67746820696e73756666696369656e74604482015290519081900360640190fd5b60008360020b8260020b12156111725750600019610685565b8260020b8260020b131561118857506001610685565b506000610685565b606061068583831c60036119b2565b600060ff826111ae8686611a79565b02816111b657fe5b06949350505050565b60606111fd6111f8846102c76111d5888a610b5d565b6111f26111e2888a610b5d565b6111ec8d8d610b5d565b90611a80565b90610c14565b61068c565b9695505050505050565b606061121282611ad9565b61122e836000015184602001518560600151866080015161218d565b611245846060015185608001518660a001516124b8565b6112638560c001518660e00151876101000151886101200151612608565b61128361127487610140015161068c565b8760c001518860e0015161295b565b6112968761014001518860400151612d8c565b6040516020018087805190602001908083835b602083106112c85780518252601f1990920191602091820191016112a9565b51815160209384036101000a600019018019909216911617905289519190930192890191508083835b602083106113105780518252601f1990920191602091820191016112f1565b51815160209384036101000a600019018019909216911617905288519190930192880191508083835b602083106113585780518252601f199092019160209182019101611339565b51815160209384036101000a600019018019909216911617905287519190930192870191508083835b602083106113a05780518252601f199092019160209182019101611381565b51815160209384036101000a600019018019909216911617905286519190930192860191508083835b602083106113e85780518252601f1990920191602091820191016113c9565b51815160209384036101000a600019018019909216911617905285519190930192850191508083835b602083106114305780518252601f199092019160209182019101611411565b5181516020939093036101000a60001901801990911692169190911790527f3c2f7376673e000000000000000000000000000000000000000000000000000092019182525060408051808303601919018152600690920190529998505050505050505050565b60008060008360020b126114ad578260020b6114b5565b8260020b6000035b9050620d89e881111561150f576040805162461bcd60e51b815260206004820152600160248201527f5400000000000000000000000000000000000000000000000000000000000000604482015290519081900360640190fd5b60006001821661152357600160801b611535565b6ffffcb933bd6fad37aa2d162d1a5940015b70ffffffffffffffffffffffffffffffffff1690506002821615611569576ffff97272373d413259a46990580e213a0260801c5b6004821615611588576ffff2e50f5f656932ef12357cf3c7fdcc0260801c5b60088216156115a7576fffe5caca7e10e4e61c3624eaa0941cd00260801c5b60108216156115c6576fffcb9843d60f6159c9db58835c9266440260801c5b60208216156115e5576fff973b41fa98c081472e6896dfb254c00260801c5b6040821615611604576fff2ea16466c96a3843ec78b326b528610260801c5b6080821615611623576ffe5dee046a99a2a811c461f1969c30530260801c5b610100821615611643576ffcbe86c7900a88aedcffc83b479aa3a40260801c5b610200821615611663576ff987a7253ac413176f2b074cf7815e540260801c5b610400821615611683576ff3392b0822b70005940c7a398e4b70f30260801c5b6108008216156116a3576fe7159475a2c29b7443b29c7fa6e889d90260801c5b6110008216156116c3576fd097f3bdfd2022b8845ad8f792aa58250260801c5b6120008216156116e3576fa9f746462d870fdf8a65dc1f90e061e50260801c5b614000821615611703576f70d869a156d2a1b890bb3df62baf32f70260801c5b618000821615611723576f31be135f97d08fd981231505542fcfa60260801c5b62010000821615611744576f09aa508b5b7a84e1c677de54f3e99bc90260801c5b62020000821615611764576e5d6af8dedb81196699c329225ee6040260801c5b62040000821615611783576d2216e584f5fa1ea926041bedfe980260801c5b620800008216156117a0576b048a170391f7dc42444e8fa20260801c5b60008460020b13156117bb5780600019816117b757fe5b0490505b6401000000008106156117cf5760016117d2565b60005b60ff16602082901c0192505050919050565b606060006117f3858585612e04565b9050600061180b828368010000000000000000612f06565b90506c010000000000000000000000008210801561184c576118458272047bf19673df52e37f2410011d100000000000600160801b612f06565b9150611861565b61185e82620186a0600160801b612f06565b91505b8160005b811561187957600101600a82049150611865565b6000190160008061188a8684612fb5565b91509150801561189b576001909201915b6118a3613e02565b8515611910576118c26118ba602b60ff8716610b5d565b600790610bba565b60ff9081166020830152600260808301526118e8906001906102c790602b908816610b5d565b60ff90811660a0830152602082015161190391166001610b5d565b60ff166040820152611987565b60098460ff16106119595761192960ff85166004610b5d565b60ff166020820181905260056080830152611945906001610b5d565b60ff1660a082015260046040820152611987565b6006602082015260056040820181905261197e906001906102c79060ff881690610b5d565b60ff1660608201525b82815285151560c0820152600060e08201526119a281610c7b565b9c9b505050505050505050505050565b606060008260020267ffffffffffffffff811180156119d057600080fd5b506040519080825280601f01601f1916602001820160405280156119fb576020820181803683370190505b5080519091505b8015611a71577f303132333435363738396162636465660000000000000000000000000000000085600f1660108110611a3757fe5b1a60f81b826001830381518110611a4a57fe5b60200101906001600160f81b031916908160001a90535060049490941c9360001901611a02565b509392505050565b1c60ff1690565b600082611a8f57506000610486565b82820282848281611a9c57fe5b04146106855760405162461bcd60e51b815260040180806020018281038252602181526020018061548a6021913960400191505060405180910390fd5b6060611b6e82610160015160405160200180806150446081913960810182805190602001908083835b60208310611b215780518252601f199092019160209182019101611b02565b6001836020036101000a038019825116818451168082178552505050505050905001806813979f1e17b9bb339f60b91b8152506009019150506040516020818303038152906040526109d8565b611cda836101e001518461020001518561018001516040516020018080614b816063913960630184805190602001908083835b60208310611bc05780518252601f199092019160209182019101611ba1565b51815160209384036101000a600019018019909216911617905265272063793d2760d01b919093019081528551600690910192860191508083835b60208310611c1a5780518252601f199092019160209182019101611bfb565b51815160209384036101000a60001901801990921691161790527f2720723d273132307078272066696c6c3d272300000000000000000000000000919093019081528451601390910192850191508083835b60208310611c8b5780518252601f199092019160209182019101611c6c565b6001836020036101000a038019825116818451168082178552505050505050905001806813979f1e17b9bb339f60b91b81525060090193505050506040516020818303038152906040526109d8565b611d2b846102200151856102400151866101a001516040516020018080614b8160639139606301848051906020019080838360208310611bc05780518252601f199092019160209182019101611ba1565b611e4a856102600151866102800151876101c001516040516020018080614b816063913960630184805190602001908083835b60208310611d7d5780518252601f199092019160209182019101611d5e565b51815160209384036101000a600019018019909216911617905265272063793d2760d01b919093019081528551600690910192860191508083835b60208310611dd75780518252601f199092019160209182019101611db8565b51815160001960209485036101000a019081169019919091161790527f2720723d273130307078272066696c6c3d272300000000000000000000000000939091019283528451601390930192908501915080838360208310611c8b5780518252601f199092019160209182019101611c6c565b6101608601516040516020018060566148fc8239605601602c6152ab82397f3c646566733e0000000000000000000000000000000000000000000000000000602c820152603201604b614ff98239604b0186805190602001908083835b60208310611ec65780518252601f199092019160209182019101611ea7565b6001836020036101000a03801982511681845116808217855250505050505090500180615b31603e9139603e0185805190602001908083835b60208310611f1e5780518252601f199092019160209182019101611eff565b6001836020036101000a038019825116818451168082178552505050505050905001806150c5603e9139603e0184805190602001908083835b60208310611f765780518252601f199092019160209182019101611f57565b5181516020939093036101000a60001901801990911692169190911790527f22202f3e00000000000000000000000000000000000000000000000000000000920191825250600401603b6147f48239603b0183805190602001908083835b60208310611ff35780518252601f199092019160209182019101611fd4565b6001836020036101000a03801982511681845116808217855250505050505090500180614c4160999139609901607f6156e28239607f016088615aa982396088016041614cda8239604101605d615c698239605d01607261578e8239607201604961475d823960490160be614f3b823960be016071614a0d8239607101607561562582396075016066614d1b823960660160a46152d7823960a4016085615b6f82397f3c6720636c69702d706174683d2275726c2823636f726e65727329223e00000060858201527f3c726563742066696c6c3d22000000000000000000000000000000000000000060a2820152825160ae9091019060208401908083835b602083106121115780518252601f1990920191602091820191016120f2565b6001836020036101000a03801982511681845116808217855250505050505090500180614d8160319139603101604e6147a68239604e01605d614be48239605d01604161522a8239604101605261510382396052016075615bf48239607501955050505050506040516020818303038152906040529050919050565b60608382858488878a896040516020018080615d4c60259139602501607d614ebe8239607d0189805190602001908083835b602083106121de5780518252601f1990920191602091820191016121bf565b51815160209384036101000a600019018019909216911617905264010714051160dd1b919093019081528a516005909101928b0191508083835b602083106122375780518252601f199092019160209182019101612218565b6001836020036101000a03801982511681845116808217855250505050505090500180614db2607991396079016086615cc6823960860187805190602001908083835b602083106122995780518252601f19909201916020918201910161227a565b51815160209384036101000a600019018019909216911617905264010714051160dd1b919093019081528851600590910192890191508083835b602083106122f25780518252601f1990920191602091820191016122d3565b6001836020036101000a0380198251168184511680821785525050505050509050018061498860859139608501607b6159178239607b0185805190602001908083835b602083106123545780518252601f199092019160209182019101612335565b51815160209384036101000a600019018019909216911617905264010714051160dd1b919093019081528651600590910192870191508083835b602083106123ad5780518252601f19909201916020918201910161238e565b6001836020036101000a03801982511681845116808217855250505050505090500180614ad2605d9139605d0160a3615582823960a30183805190602001908083835b6020831061240f5780518252601f1990920191602091820191016123f0565b51815160209384036101000a600019018019909216911617905264010714051160dd1b919093019081528451600590910192850191508083835b602083106124685780518252601f199092019160209182019101612449565b6001836020036101000a038019825116818451168082178552505050505050905001806146d2608b9139608b01985050505050505050506040516020818303038152906040529050949350505050565b6060838383604051602001808061482f60cd913960cd0184805190602001908083835b602083106124fa5780518252601f1990920191602091820191016124db565b6001836020036101000a03801982511681845116808217855250505050505090500180602f60f81b81525060010183805190602001908083835b602083106125535780518252601f199092019160209182019101612534565b6001836020036101000a03801982511681845116808217855250505050505090500180615ef56077913960770182805190602001908083835b602083106125ab5780518252601f19909201916020918201910161258c565b5181516020939093036101000a60001901801990911692169190911790526a1e17ba32bc3a1f1e17b39f60a91b920191825250600b016073615d958239607301935050505060405160208183030381529060405290509392505050565b606060008260000b60011461269a578260000b6000191461265e576040518060400160405280600581526020017f236e6f6e65000000000000000000000000000000000000000000000000000000815250612695565b6040518060400160405280600a81526020017f23666164652d646f776e000000000000000000000000000000000000000000008152505b6126d1565b6040518060400160405280600881526020017f23666164652d75700000000000000000000000000000000000000000000000008152505b905060006126e0878787613026565b9050818183836126ef88613274565b60405160200180807f3c67206d61736b3d2275726c2800000000000000000000000000000000000000815250600d0186805190602001908083835b602083106127495780518252601f19909201916020918201910161272a565b5181516020939093036101000a600019018019909116921691909117905261149160f11b920191825250600201607761537b823960770185805190602001908083835b602083106127ab5780518252601f19909201916020918201910161278c565b6001836020036101000a03801982511681845116808217855250505050505090500180614a7e60549139605401807f3c2f673e3c67206d61736b3d2275726c2800000000000000000000000000000081525060110184805190602001908083835b6020831061282b5780518252601f19909201916020918201910161280c565b5181516020939093036101000a600019018019909116921691909117905261149160f11b92019182525060020160296153f2823960290160456154458239604501807f3c7061746820643d22000000000000000000000000000000000000000000000081525060090183805190602001908083835b602083106128bf5780518252601f1990920191602091820191016128a0565b6001836020036101000a0380198251168184511680821785525050505050509050018061569a6048913960480182805190602001908083835b602083106129175780518252601f1990920191602091820191016128f8565b6001836020036101000a0380198251168184511680821785525050505050509050019550505050505060405160208183030381529060405292505050949350505050565b6060600061296884613748565b9050600061297584613748565b865183518251929350600490910191600a91820191016000806129988a8a613852565b915091506129ab8560040160070261068c565b8b6129bb8660040160070261068c565b896129cb8760040160070261068c565b8a87876040516020018080615761602d9139602d01806c1e3932b1ba103bb4b23a341e9160991b815250600d0189805190602001908083835b60208310612a235780518252601f199092019160209182019101612a04565b6001836020036101000a03801982511681845116808217855250505050505090500180615155603d9139603d01608d615e088239608d0188805190602001908083835b60208310612a855780518252601f199092019160209182019101612a66565b5181516020939093036101000a60001901801990911692169190911790526a1e17ba32bc3a1f1e17b39f60a91b920191825250600b01602d615fa48239602d01806c1e3932b1ba103bb4b23a341e9160991b815250600d0187805190602001908083835b60208310612b085780518252601f199092019160209182019101612ae9565b6001836020036101000a03801982511681845116808217855250505050505090500180615155603d9139603d016093614e2b823960930186805190602001908083835b60208310612b6a5780518252601f199092019160209182019101612b4b565b5181516020939093036101000a60001901801990911692169190911790526a1e17ba32bc3a1f1e17b39f60a91b920191825250600b01602d614b2f8239602d01806c1e3932b1ba103bb4b23a341e9160991b815250600d0185805190602001908083835b60208310612bed5780518252601f199092019160209182019101612bce565b6001836020036101000a03801982511681845116808217855250505050505090500180615155603d9139603d016093615992823960930184805190602001908083835b60208310612c4f5780518252601f199092019160209182019101612c30565b6001836020036101000a03801982511681845116808217855250505050505090500180615f6c603891396038016060615e958239606001606461551e82396064016025614b5c823960250183805190602001908083835b60208310612cc55780518252601f199092019160209182019101612ca6565b51815160209384036101000a60001901801990921691161790527f70782c2000000000000000000000000000000000000000000000000000000000919093019081528451600490910192850191508083835b60208310612d365780518252601f199092019160209182019101612d17565b6001836020036101000a0380198251168184511680821785525050505050509050018061495260369139603601985050505050505050506040516020818303038152906040529750505050505050509392505050565b6060612d988383613c83565b15612dee5760405160200180608d61588a8239608d0160736154ab823960730160716151b98239607101608a6158008239608a016084615a25823960840190506040516020818303038152906040529050610486565b5060408051602081019091526000815292915050565b600080612e1f612e1a60ff868116908616613ce6565b613d4b565b9050600081118015612e32575060128111155b15612ef3578260ff168460ff161115612e9c57612e66612e53826002610c14565b6001600160a01b03871690600a0a611a80565b91506002810660011415612e9757612e94827003298b075b4b6a5240945790619b37fd4a600160801b612f06565b91505b612eee565b612ebd612eaa826002610c14565b6001600160a01b03871690600a0a610c14565b91506002810660011415612eee57612eeb82600160801b7003298b075b4b6a5240945790619b37fd4a612f06565b91505b611a71565b50506001600160a01b0390921692915050565b6000808060001985870986860292508281109083900303905080612f3c5760008411612f3157600080fd5b508290049050610685565b808411612f4857600080fd5b6000848688096000868103871696879004966002600389028118808a02820302808a02820302808a02820302808a02820302808a02820302808a02909103029181900381900460010186841190950394909402919094039290920491909117919091029150509392505050565b600080600060058460ff161115612fdd57612fda8560ff600419870116600a0a610c14565b94505b60006004600a8706119050612ff386600a610c14565b95508015613002578560010195505b85620186a0141561301857600a86049550600191505b5084925090505b9250929050565b606060008260020b85850360020b8161303b57fe5b05905060048160020b13613086576040518060400160405280601a81526020017f4d312031433431203431203130352031303520313435203134350000000000008152509150611a71565b60088160020b136130ce576040518060400160405280601981526020017f4d312031433333203439203937203131332031343520313435000000000000008152509150611a71565b60108160020b13613116576040518060400160405280601981526020017f4d312031433333203537203839203131332031343520313435000000000000008152509150611a71565b60208160020b1361315e576040518060400160405280601981526020017f4d312031433235203635203831203132312031343520313435000000000000008152509150611a71565b60408160020b136131a6576040518060400160405280601981526020017f4d312031433137203733203733203132392031343520313435000000000000008152509150611a71565b60808160020b136131ee576040518060400160405280601881526020017f4d312031433920383120363520313337203134352031343500000000000000008152509150611a71565b6101008160020b13613237576040518060400160405280601a81526020017f4d31203143312038392035372e352031343520313435203134350000000000008152509150611a71565b505060408051808201909152601881527f4d3120314331203937203439203134352031343520313435000000000000000060208201529392505050565b604080518082018252600281527f37330000000000000000000000000000000000000000000000000000000000006020808301919091528251808401845260038082527f313930000000000000000000000000000000000000000000000000000000000082840152845180860186528181527f32313700000000000000000000000000000000000000000000000000000000008185015285518087019096529085527f3333340000000000000000000000000000000000000000000000000000000000928501929092526060939091906001600087900b148061335b57508560000b600019145b15613552578560000b600019146133725781613374565b835b8660000b600019146133865781613388565b835b8760000b6000191461339a578361339c565b855b8860000b600019146133ae57836133b0565b855b60405160200180806b1e31b4b931b6329031bc1e9160a11b815250600c0185805190602001908083835b602083106133f95780518252601f1990920191602091820191016133da565b51815160209384036101000a600019018019909216911617905267383c111031bc9e9160c11b919093019081528651600890910192870191508083835b602083106134555780518252601f199092019160209182019101613436565b6001836020036101000a038019825116818451168082178552505050505050905001806151926027913960270183805190602001908083835b602083106134ad5780518252601f19909201916020918201910161348e565b51815160209384036101000a600019018019909216911617905267383c111031bc9e9160c11b919093019081528451600890910192850191508083835b602083106135095780518252601f1990920191602091820191016134ea565b6001836020036101000a0380198251168184511680821785525050505050509050018061541b602a9139602a01945050505050604051602081830303815290604052945061373f565b8383838360405160200180806b1e31b4b931b6329031bc1e9160a11b815250600c0185805190602001908083835b6020831061359f5780518252601f199092019160209182019101613580565b51815160209384036101000a600019018019909216911617905267383c111031bc9e9160c11b919093019081528651600890910192870191508083835b602083106135fb5780518252601f1990920191602091820191016135dc565b51815160209384036101000a60001901801990921691161790527f70782220723d22347078222066696c6c3d22776869746522202f3e0000000000919093019081526b1e31b4b931b6329031bc1e9160a11b601b8201528551602790910192860191508083835b602083106136815780518252601f199092019160209182019101613662565b51815160209384036101000a600019018019909216911617905267383c111031bc9e9160c11b919093019081528451600890910192850191508083835b602083106136dd5780518252601f1990920191602091820191016136be565b6001836020036101000a038019825116818451168082178552505050505050905001807f70782220723d22347078222066696c6c3d22776869746522202f3e0000000000815250601b0194505050505060405160208183030381529060405294505b50505050919050565b6060600060405180602001604052806000815250905060008360020b121561378e5782600019029250604051806040016040528060018152602001602d60f81b81525090505b8061379b8460020b61068c565b6040516020018083805190602001908083835b602083106137cd5780518252601f1990920191602091820191016137ae565b51815160209384036101000a600019018019909216911617905285519190930192850191508083835b602083106138155780518252601f1990920191602091820191016137f6565b6001836020036101000a03801982511681845116808217855250505050505090500192505050604051602081830303815290604052915050919050565b60608060006002858501810b0590506201e847198160020b12156138ca57604051806040016040528060018152602001600760fb1b8152506040518060400160405280600181526020017f3700000000000000000000000000000000000000000000000000000000000000815250925092505061301f565b620124f7198160020b121561393357604051806040016040528060018152602001600760fb1b8152506040518060400160405280600481526020017f31302e3500000000000000000000000000000000000000000000000000000000815250925092505061301f565b6161a7198160020b121561399b57604051806040016040528060018152602001600760fb1b8152506040518060400160405280600581526020017f31342e3235000000000000000000000000000000000000000000000000000000815250925092505061301f565b611387198160020b1215613a04576040518060400160405280600281526020017f313000000000000000000000000000000000000000000000000000000000000081525060405180604001604052806002815260200161062760f31b815250925092505061301f565b60008160020b1215613a6b576040518060400160405280600281526020017f313100000000000000000000000000000000000000000000000000000000000081525060405180604001604052806002815260200161323160f01b815250925092505061301f565b6113888160020b1215613aee576040518060400160405280600281526020017f31330000000000000000000000000000000000000000000000000000000000008152506040518060400160405280600281526020017f3233000000000000000000000000000000000000000000000000000000000000815250925092505061301f565b6161a88160020b1215613b71576040518060400160405280600281526020017f31350000000000000000000000000000000000000000000000000000000000008152506040518060400160405280600281526020017f3235000000000000000000000000000000000000000000000000000000000000815250925092505061301f565b620124f88160020b1215613bda5760405180604001604052806002815260200161062760f31b8152506040518060400160405280600281526020017f3236000000000000000000000000000000000000000000000000000000000000815250925092505061301f565b6201e8488160020b1215613c285760405180604001604052806002815260200161323160f01b81525060405180604001604052806002815260200161323760f01b815250925092505061301f565b6040518060400160405280600281526020017f323400000000000000000000000000000000000000000000000000000000000081525060405180604001604052806002815260200161323760f01b815250925092505061301f565b6040805160208082018590526bffffffffffffffffffffffff19606085901b16828401528251603481840301815260549092019092528051910120600090613cca84613d62565b60020260010160ff1660001981613cdd57fe5b04119392505050565b6000818303818312801590613cfb5750838113155b80613d105750600083128015613d1057508381135b6106855760405162461bcd60e51b8152600401808060200182810382526024815260200180615d716024913960400191505060405180910390fd5b600080821215613d5e5781600003610486565b5090565b6000808211613d7057600080fd5b600160801b8210613d8357608091821c91015b680100000000000000008210613d9b57604091821c91015b6401000000008210613daf57602091821c91015b620100008210613dc157601091821c91015b6101008210613dd257600891821c91015b60108210613de257600491821c91015b60048210613df257600291821c91015b6002821061016b57600101919050565b6040805161010081018252600080825260208201819052918101829052606081018290526080810182905260a0810182905260c0810182905260e081019190915290565b80356001600160a01b038116811461016b57600080fd5b8035801515811461016b57600080fd5b8035600281900b811461016b57600080fd5b600082601f830112613e8f578081fd5b813567ffffffffffffffff811115613ea357fe5b613eb6601f8201601f191660200161467d565b818152846020838601011115613eca578283fd5b816020850160208301379081016020019190915292915050565b803562ffffff8116811461016b57600080fd5b803560ff8116811461016b57600080fd5b600060208284031215613f19578081fd5b813567ffffffffffffffff80821115613f30578283fd5b81840191506101c0808387031215613f46578384fd5b613f4f8161467d565b905082358152613f6160208401613e46565b6020820152613f7260408401613e46565b6040820152606083013582811115613f88578485fd5b613f9487828601613e7f565b606083015250608083013582811115613fab578485fd5b613fb787828601613e7f565b608083015250613fc960a08401613ef7565b60a0820152613fda60c08401613ef7565b60c0820152613feb60e08401613e5d565b60e08201526101009150614000828401613e6d565b828201526101209150614014828401613e6d565b828201526101409150614028828401613e6d565b82820152610160915061403c828401613e6d565b828201526101809150614050828401613ee4565b828201526101a09150614064828401613e46565b91810191909152949350505050565b600081516140858185602086016146a1565b9290920192915050565b7fe29aa0efb88f20444953434c41494d45523a204475652064696c6967656e636581527f20697320696d7065726174697665207768656e20617373657373696e6720746860208201527f6973204e46542e204d616b65207375726520746f6b656e20616464726573736560408201527f73206d617463682074686520657870656374656420746f6b656e732c2061732060608201527f746f6b656e2073796d626f6c73206d617920626520696d6974617465642e00006080820152609e0190565b7f5c6e5c6e00000000000000000000000000000000000000000000000000000000815260040190565b60007f54686973204e465420726570726573656e74732061206c69717569646974792082527f706f736974696f6e20696e206120556e69737761702056332000000000000000602083015285516141d7816039850160208a016146a1565b602d60f81b60399184019182015285516141f881603a840160208a016146a1565b7f20706f6f6c2e2000000000000000000000000000000000000000000000000000603a92909101918201527f546865206f776e6572206f662074686973204e46542063616e206d6f6469667960418201527f206f722072656465656d2074686520706f736974696f6e2e5c6e00000000000060618201527f5c6e506f6f6c20416464726573733a2000000000000000000000000000000000607b82015284516142a881608b8401602089016146a1565b612e3760f11b608b92909101918201526103c6608d820185614073565b60007f7b226e616d65223a220000000000000000000000000000000000000000000000825285516142fd816009850160208a016146a1565b7f222c20226465736372697074696f6e223a220000000000000000000000000000600991840191820152855161433a81601b840160208a016146a1565b855191019061435081601b8401602089016146a1565b7f222c2022696d616765223a202200000000000000000000000000000000000000601b92909101918201527f646174613a696d6167652f7376672b786d6c3b6261736536342c000000000000602882015283516143b48160428401602088016146a1565b7f227d000000000000000000000000000000000000000000000000000000000000604292909101918201526044019695505050505050565b60007f556e6973776170202d20000000000000000000000000000000000000000000008252865161442481600a850160208b016146a1565b80830190507f202d20000000000000000000000000000000000000000000000000000000000080600a830152875161446381600d850160208c016146a1565b602f60f81b600d9390910192830152865161448581600e850160208b016146a1565b600e92019182015284516144a08160118401602089016146a1565b7f3c3e0000000000000000000000000000000000000000000000000000000000006011929091019182015283516144de8160138401602088016146a1565b01601301979650505050505050565b60007f20416464726573733a2000000000000000000000000000000000000000000000808352875161452681600a860160208c016146a1565b612e3760f11b600a91850191820152875161454881600c840160208c016146a1565b01600c810191909152855190614565826016830160208a016146a1565b8181019150507f5c6e46656520546965723a200000000000000000000000000000000000000000601682015284516145a48160228401602089016146a1565b7f5c6e546f6b656e2049443a2000000000000000000000000000000000000000006022929091019182015283516145e281602e8401602088016146a1565b6145f86145f3602e83850101614150565b61408f565b9998505050505050505050565b60007f646174613a6170706c69636174696f6e2f6a736f6e3b6261736536342c0000008252825161463d81601d8501602087016146a1565b91909101601d0192915050565b60006020825282518060208401526146698160408501602087016146a1565b601f01601f19169190910160400192915050565b60405181810167ffffffffffffffff8111828210171561469957fe5b604052919050565b60005b838110156146bc5781810151838201526020016146a4565b838111156146cb576000848401525b5050505056fe203c616e696d6174652061646469746976653d2273756d22206174747269627574654e616d653d2273746172744f6666736574222066726f6d3d2230252220746f3d22313030252220626567696e3d22307322206475723d223330732220726570656174436f756e743d22696e646566696e69746522202f3e3c2f74657874506174683e3c2f746578743e3c73746f70206f66667365743d222e39222073746f702d636f6c6f723d227768697465222073746f702d6f7061636974793d223022202f3e3c2f6c696e6561724772616469656e743e3c72656374207374796c653d2266696c7465723a2075726c28236631292220783d223070782220793d22307078222077696474683d22323930707822206865696768743d22353030707822202f3e3c6665496d61676520726573756c743d2270332220786c696e6b3a687265663d22646174613a696d6167652f7376672b786d6c3b6261736536342c3c67206d61736b3d2275726c2823666164652d73796d626f6c29223e3c726563742066696c6c3d226e6f6e652220783d223070782220793d22307078222077696474683d22323930707822206865696768743d22323030707822202f3e203c7465787420793d22373070782220783d2233327078222066696c6c3d2277686974652220666f6e742d66616d696c793d2227436f7572696572204e6577272c206d6f6e6f73706163652220666f6e742d7765696768743d223230302220666f6e742d73697a653d2233367078223e3c7376672077696474683d2232393022206865696768743d22353030222076696577426f783d2230203020323930203530302220786d6c6e733d22687474703a2f2f7777772e77332e6f72672f323030302f7376672270782c2030707829222063783d22307078222063793d223070782220723d22347078222066696c6c3d227768697465222f3e3c2f673e203c616e696d6174652061646469746976653d2273756d22206174747269627574654e616d653d2273746172744f6666736574222066726f6d3d2230252220746f3d22313030252220626567696e3d22307322206475723d223330732220726570656174436f756e743d22696e646566696e69746522202f3e203c2f74657874506174683e3c6d61736b2069643d22666164652d757022206d61736b436f6e74656e74556e6974733d226f626a656374426f756e64696e67426f78223e3c726563742077696474683d223122206865696768743d2231222066696c6c3d2275726c2823677261642d75702922202f3e3c2f6d61736b3e22207374726f6b653d227267626128302c302c302c302e332922207374726f6b652d77696474683d2233327078222066696c6c3d226e6f6e6522207374726f6b652d6c696e656361703d22726f756e6422202f3e203c616e696d6174652061646469746976653d2273756d22206174747269627574654e616d653d2273746172744f6666736574222066726f6d3d2230252220746f3d22313030252220626567696e3d22307322206475723d2233307322203c67207374796c653d227472616e73666f726d3a7472616e736c61746528323970782c20343434707829223e3c636972636c65207374796c653d227472616e73666f726d3a7472616e736c6174653364283c7376672077696474683d2732393027206865696768743d27353030272076696577426f783d2730203020323930203530302720786d6c6e733d27687474703a2f2f7777772e77332e6f72672f323030302f737667273e3c636972636c652063783d27203c67207374796c653d2266696c7465723a75726c2823746f702d726567696f6e2d626c7572293b207472616e73666f726d3a7363616c6528312e35293b207472616e73666f726d2d6f726967696e3a63656e74657220746f703b223e22202f3e3c6665426c656e64206d6f64653d226f7665726c61792220696e3d2270302220696e323d22703122202f3e3c6665426c656e64206d6f64653d226578636c7573696f6e2220696e323d22703222202f3e3c6665426c656e64206d6f64653d226f7665726c61792220696e323d2270332220726573756c743d22626c656e644f757422202f3e3c6665476175737369616e426c7572203c706174682069643d226d696e696d61702220643d224d3233342034343443323334203435372e393439203234322e323120343633203235332034363322202f3e3c6d61736b2069643d226e6f6e6522206d61736b436f6e74656e74556e6974733d226f626a656374426f756e64696e67426f78223e3c726563742077696474683d223122206865696768743d2231222066696c6c3d22776869746522202f3e3c2f6d61736b3e2220783d223070782220793d22307078222077696474683d22323930707822206865696768743d22353030707822202f3e203c616e696d6174652061646469746976653d2273756d22206174747269627574654e616d653d2273746172744f6666736574222066726f6d3d2230252220746f3d22313030252220626567696e3d22307322206475723d223330732220726570656174436f756e743d22696e646566696e69746522202f3e3c7465787420783d22313270782220793d22313770782220666f6e742d66616d696c793d2227436f7572696572204e6577272c206d6f6e6f73706163652220666f6e742d73697a653d2231327078222066696c6c3d227768697465223e3c747370616e2066696c6c3d2272676261283235352c3235352c3235352c302e3629223e4d696e205469636b3a203c2f747370616e3e3c74657874506174682073746172744f66667365743d222d31303025222066696c6c3d2277686974652220666f6e742d66616d696c793d2227436f7572696572204e6577272c206d6f6e6f73706163652220666f6e742d73697a653d22313070782220786c696e6b3a687265663d2223746578742d706174682d61223e3c6c696e6561724772616469656e742069643d22677261642d646f776e222078313d2230222078323d2231222079313d2230222079323d2231223e3c73746f70206f66667365743d22302e30222073746f702d636f6c6f723d227768697465222073746f702d6f7061636974793d223122202f3e3c73746f70206f66667365743d22302e39222073746f702d636f6c6f723d227768697465222073746f702d6f7061636974793d223022202f3e3c2f6c696e6561724772616469656e743e3c66696c7465722069643d226631223e3c6665496d61676520726573756c743d2270302220786c696e6b3a687265663d22646174613a696d6167652f7376672b786d6c3b6261736536342c3c7376672077696474683d2732393027206865696768743d27353030272076696577426f783d2730203020323930203530302720786d6c6e733d27687474703a2f2f7777772e77332e6f72672f323030302f737667273e3c726563742077696474683d27323930707827206865696768743d273530307078272066696c6c3d2723222f3e3c6665496d61676520726573756c743d2270322220786c696e6b3a687265663d22646174613a696d6167652f7376672b786d6c3b6261736536342c3c656c6c697073652063783d22353025222063793d22307078222072783d223138307078222072793d223132307078222066696c6c3d222330303022206f7061636974793d22302e383522202f3e3c2f673e707822206865696768743d2232367078222072783d22387078222072793d22387078222066696c6c3d227267626128302c302c302c302e362922202f3e70782220723d22347078222066696c6c3d22776869746522202f3e3c636972636c652063783d2231312e333437384c32342031324c31342e343334312031322e363532324c32322e333932332031384c31332e373831392031332e373831394c31382032322e333932334c31322e363532322031342e343334314c31322032344c31312e333437382031342e343334314c362032322e33393c726563742066696c6c3d226e6f6e652220783d223070782220793d22307078222077696474683d22323930707822206865696768743d22353030707822202f3e4142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738392b2f20786d6c6e733a786c696e6b3d27687474703a2f2f7777772e77332e6f72672f313939392f786c696e6b273e3c6c696e6561724772616469656e742069643d22677261642d73796d626f6c223e3c73746f70206f66667365743d22302e37222073746f702d636f6c6f723d227768697465222073746f702d6f7061636974793d223122202f3e3c73746f70206f66667365743d222e3935222073746f702d636f6c6f723d227768697465222073746f702d6f7061636974793d223022202f3e3c2f6c696e6561724772616469656e743e207374796c653d227472616e73666f726d3a7472616e736c61746528373270782c313839707829223e3c7265637420783d222d313670782220793d222d31367078222077696474683d22313830707822206865696768743d223138307078222066696c6c3d226e6f6e6522202f3e3c7061746820643d22207374796c653d227472616e73666f726d3a7472616e736c61746528373270782c313839707829223e70782220723d2232347078222066696c6c3d226e6f6e6522207374726f6b653d22776869746522202f3e3c7265637420783d222d313670782220793d222d31367078222077696474683d22313830707822206865696768743d223138307078222066696c6c3d226e6f6e6522202f3e536166654d6174683a206d756c7469706c69636174696f6e206f766572666c6f773c673e3c70617468207374796c653d227472616e73666f726d3a7472616e736c617465283670782c367078292220643d224d313220304c31322e3635323220392e35363538374c313820312e363037374c31332e373831392031302e323138314c32322e3339323320364c31342e34333431203c70617468207374726f6b652d6c696e656361703d22726f756e642220643d224d38203943382e30303030342032322e393439342031362e32303939203238203237203238222066696c6c3d226e6f6e6522207374726f6b653d22776869746522202f3e20726570656174436f756e743d22696e646566696e69746522202f3e3c2f74657874506174683e3c74657874506174682073746172744f66667365743d222d353025222066696c6c3d2277686974652220666f6e742d66616d696c793d2227436f7572696572204e6577272c206d6f6e6f73706163652220666f6e742d73697a653d22313070782220786c696e6b3a687265663d2223746578742d706174682d61223e3c6d61736b2069643d22666164652d646f776e22206d61736b436f6e74656e74556e6974733d226f626a656374426f756e64696e67426f78223e3c726563742077696474683d223122206865696768743d2231222066696c6c3d2275726c2823677261642d646f776e2922202f3e3c2f6d61736b3e22207374726f6b653d2272676261283235352c3235352c3235352c3129222066696c6c3d226e6f6e6522207374726f6b652d6c696e656361703d22726f756e6422202f3e3c2f673e696e3d22626c656e644f75742220737464446576696174696f6e3d22343222202f3e3c2f66696c7465723e203c636c6970506174682069643d22636f726e657273223e3c726563742077696474683d2232393022206865696768743d22353030222072783d223432222072793d22343222202f3e3c2f636c6970506174683e203c67207374796c653d227472616e73666f726d3a7472616e736c61746528323970782c20333834707829223e3c6c696e6561724772616469656e742069643d22677261642d7570222078313d2231222078323d2230222079313d2231222079323d2230223e3c73746f70206f66667365743d22302e30222073746f702d636f6c6f723d227768697465222073746f702d6f7061636974793d223122202f3e32334c31302e323138312031332e373831394c312e363037372031384c392e35363538372031322e363532324c302031324c392e35363538372031312e333437384c312e3630373720364c31302e323138312031302e323138314c3620312e363037374c31312e3334373820392e35363538374c313220305a222066696c6c3d22776869746522202f3e3c67207374796c653d227472616e73666f726d3a7472616e736c6174652832323670782c20333932707829223e3c726563742077696474683d223336707822206865696768743d2233367078222072783d22387078222072793d22387078222066696c6c3d226e6f6e6522207374726f6b653d2272676261283235352c3235352c3235352c302e322922202f3e3c74657874506174682073746172744f66667365743d22353025222066696c6c3d2277686974652220666f6e742d66616d696c793d2227436f7572696572204e6577272c206d6f6e6f73706163652220666f6e742d73697a653d22313070782220786c696e6b3a687265663d2223746578742d706174682d61223e3c7465787420783d22313270782220793d22313770782220666f6e742d66616d696c793d2227436f7572696572204e6577272c206d6f6e6f73706163652220666f6e742d73697a653d2231327078222066696c6c3d227768697465223e3c747370616e2066696c6c3d2272676261283235352c3235352c3235352c302e3629223e4d6178205469636b3a203c2f747370616e3e3c616e696d6174655472616e73666f726d206174747269627574654e616d653d227472616e73666f726d2220747970653d22726f74617465222066726f6d3d22302031382031382220746f3d2233363020313820313822206475723d223130732220726570656174436f756e743d22696e646566696e697465222f3e3c2f673e3c2f673e3c706174682069643d22746578742d706174682d612220643d224d34302031322048323530204132382032382030203020312032373820343020563436302041323820323820302030203120323530203438382048343020413238203238203020302031203132203436302056343020413238203238203020302031203430203132207a22202f3e222f3e3c6665496d61676520726573756c743d2270312220786c696e6b3a687265663d22646174613a696d6167652f7376672b786d6c3b6261736536342c3c6d61736b2069643d22666164652d73796d626f6c22206d61736b436f6e74656e74556e6974733d227573657253706163654f6e557365223e3c726563742077696474683d22323930707822206865696768743d223230307078222066696c6c3d2275726c2823677261642d73796d626f6c2922202f3e3c2f6d61736b3e3c2f646566733e3c7265637420783d22302220793d2230222077696474683d2232393022206865696768743d22353030222072783d223432222072793d223432222066696c6c3d227267626128302c302c302c302922207374726f6b653d2272676261283235352c3235352c3235352c302e322922202f3e3c2f673e3c66696c7465722069643d22746f702d726567696f6e2d626c7572223e3c6665476175737369616e426c757220696e3d22536f75726365477261706869632220737464446576696174696f6e3d22323422202f3e3c2f66696c7465723e3c2f74657874506174683e203c74657874506174682073746172744f66667365743d223025222066696c6c3d2277686974652220666f6e742d66616d696c793d2227436f7572696572204e6577272c206d6f6e6f73706163652220666f6e742d73697a653d22313070782220786c696e6b3a687265663d2223746578742d706174682d61223e3c7465787420746578742d72656e646572696e673d226f7074696d697a655370656564223e5369676e6564536166654d6174683a207375627472616374696f6e206f766572666c6f773c7265637420783d2231362220793d223136222077696474683d2232353822206865696768743d22343638222072783d223236222072793d223236222066696c6c3d227267626128302c302c302c302922207374726f6b653d2272676261283235352c3235352c3235352c302e322922202f3e3c7465787420783d22313270782220793d22313770782220666f6e742d66616d696c793d2227436f7572696572204e6577272c206d6f6e6f73706163652220666f6e742d73697a653d2231327078222066696c6c3d227768697465223e3c747370616e2066696c6c3d2272676261283235352c3235352c3235352c302e3629223e49443a203c2f747370616e3e3c726563742077696474683d223336707822206865696768743d2233367078222072783d22387078222072793d22387078222066696c6c3d226e6f6e6522207374726f6b653d2272676261283235352c3235352c3235352c302e322922202f3e3c2f746578743e3c7465787420793d2231313570782220783d2233327078222066696c6c3d2277686974652220666f6e742d66616d696c793d2227436f7572696572204e6577272c206d6f6e6f73706163652220666f6e742d7765696768743d223230302220666f6e742d73697a653d2233367078223e3c2f746578743e3c2f673e3c67207374796c653d227472616e73666f726d3a7472616e736c6174652832323670782c20343333707829223e203c67207374796c653d227472616e73666f726d3a7472616e736c61746528323970782c20343134707829223ea164736f6c6343000706000a8202c4a0d52b97735fd93c8ac1f9f7dd5abd236891563b69bfc7d07ae68cbb7ea48c6452a07de6f65bf31220fa62f7b1bddc2f5feb1321a1be144f987d79cd998aeb7326cf";
        // send_tx(&evm, sender, tx, u256_to_data(21000), 1);

        coin::destroy_freeze_cap(freeze_cap);
        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }
}

