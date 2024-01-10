module aptos_framework::evm {
    #[test_only]
    use aptos_framework::account;
    // use std::vector;
    use aptos_framework::account::{create_resource_address, exists_at, new_event_handle};
    use std::vector;
    use aptos_framework::coin;
    use aptos_framework::aptos_coin::AptosCoin;
    use aptos_std::secp256k1::{ecdsa_recover, ecdsa_signature_from_bytes, ecdsa_raw_public_key_to_bytes};
    use std::option::borrow;
    use aptos_std::aptos_hash::keccak256;
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
    use aptos_framework::rlp_encode::encode_bytes_list;

    const TX_TYPE_LEGACY: u64 = 1;

    const ADDR_LENGTH: u64 = 10001;
    const SIGNATURE: u64 = 10002;
    const INSUFFIENT_BALANCE: u64 = 10003;
    const NONCE: u64 = 10004;
    const CONTRACT_READ_ONLY: u64 = 10005;
    const CONTRACT_DEPLOYED: u64 = 10006;
    const TX_NOT_SUPPORT: u64 = 10007;
    const ACCOUNT_NOT_EXIST: u64 = 10008;
    const CONVERT_BASE: u256 = 10000000000;
    const CHAIN_ID: u64 = 0x150;


    const U256_MAX: u256 = 115792089237316195423570985008687907853269984665640564039457584007913129639935;
    const ZERO_ADDR: vector<u8> =      x"0000000000000000000000000000000000000000000000000000000000000000";
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

    native fun revert(
        message: vector<u8>
    );

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

            let message = encode_bytes_list(vector[
                u256_to_trimed_data(nonce),
                u256_to_trimed_data(gas_price),
                u256_to_trimed_data(gas_limit),
                evm_to,
                u256_to_trimed_data(value),
                data,
                CHAIN_ID_BYTES,
                x"",
                x""
                ]);
            let message_hash = keccak256(message);
            verify_signature(evm_from, message_hash, to_32bit(r), to_32bit(s), v);
            execute(to_32bit(evm_from), to_32bit(evm_to), (nonce as u64), data, value);
            transfer_to_move_addr(to_32bit(evm_from), address_of(sender), gas * CONVERT_BASE);
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
            let address_from = create_resource_address(&@aptos_framework, to_32bit(evm_from));
            assert!(exists<Account>(address_from), ACCOUNT_NOT_EXIST);
            let nonce = borrow_global<Account>(create_resource_address(&@aptos_framework, to_32bit(evm_from))).nonce;
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
        create_resource_address(&@aptos_framework, to_32bit(evm_addr))
    }

    #[view]
    public fun query(sender:vector<u8>, contract_addr: vector<u8>, data: vector<u8>): vector<u8> acquires Account, ContractEvent {
        contract_addr = to_32bit(contract_addr);
        let contract_store = borrow_global_mut<Account>(create_resource_address(&@aptos_framework, contract_addr));
        sender = to_32bit(sender);
        run(sender, sender, contract_addr, contract_store.code, data, true, 0)
    }

    #[view]
    public fun get_storage_at(addr: vector<u8>, slot: vector<u8>): vector<u8> acquires Account {
        let move_address = create_resource_address(&@aptos_framework, addr);
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
        let address_from = create_resource_address(&@aptos_framework, evm_from);
        let address_to = create_resource_address(&@aptos_framework, evm_to);
        create_account_if_not_exist(address_from);
        create_account_if_not_exist(address_to);
        verify_nonce(address_from, nonce);
        let account_store_to = borrow_global_mut<Account>(address_to);
        if(evm_to == ZERO_ADDR) {
            let evm_contract = get_contract_address(evm_from, nonce);
            let address_contract = create_resource_address(&@aptos_framework, evm_contract);
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
        // Convert the EVM address to a Move resource address.
        let move_contract_address = create_resource_address(&@aptos_framework, evm_contract_address);
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
                let evm_addr = u256_to_data(vector::pop_back(stack));
                let target_address = create_resource_address(&@aptos_framework, evm_addr);
                if(exists<Account>(target_address)) {
                    let account_store = borrow_global<Account>(target_address);
                    vector::push_back(stack, account_store.balance);
                } else {
                    vector::push_back(stack, 0)
                };
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
                let target_evm = to_32bit(slice(bytes, 12, 20));
                let target_address = create_resource_address(&@aptos_framework, target_evm);
                if(exist_contract(target_address)) {
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
                vector::push_back(stack, 1);
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
                if(readOnly) {
                    assert!(false, CONTRACT_READ_ONLY);
                };
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
                vector::push_back(stack, 0);
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
                let move_dest_addr = create_resource_address(&@aptos_framework, evm_dest_addr);
                let msg_value = if (opcode == 0xf1) vector::pop_back(stack) else 0;
                let m_pos = vector::pop_back(stack);
                let m_len = vector::pop_back(stack);
                let ret_pos = vector::pop_back(stack);
                let ret_len = vector::pop_back(stack);
                let ret_end = ret_len + ret_pos;
                let params = slice(*memory, m_pos, m_len);

                // debug::print(&utf8(b"call 222"));
                // debug::print(&opcode);
                // debug::print(&dest_addr);
                if (exist_contract(move_dest_addr)) {
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
                        if(opcode == 0xf1 && vector::length(&params) > 0) {
                            revert(x"");
                        };
                        transfer_to_evm_addr(evm_contract_address, evm_dest_addr, msg_value);
                    }
                };
                // debug::print(&opcode);
                i = i + 1
            }
                //create
            else if(opcode == 0xf0) {
                if(readOnly) {
                    assert!(false, CONTRACT_READ_ONLY);
                };
                let msg_value = vector::pop_back(stack);
                let pos = vector::pop_back(stack);
                let len = vector::pop_back(stack);
                let new_codes = slice(*memory, pos, len);
                let contract_store = borrow_global_mut<Account>(move_contract_address);
                let nonce = contract_store.nonce;
                // must be 20 bytes

                let new_evm_contract_addr = get_contract_address(evm_contract_address, nonce);
                debug::print(&utf8(b"create start"));
                debug::print(&nonce);
                debug::print(&new_evm_contract_addr);
                let new_move_contract_addr = create_resource_address(&@aptos_framework, new_evm_contract_addr);
                contract_store.nonce = contract_store.nonce + 1;

                debug::print(&exists<Account>(new_move_contract_addr));
                assert!(!exist_contract(new_move_contract_addr), CONTRACT_DEPLOYED);
                create_account_if_not_exist(new_move_contract_addr);
                create_event_if_not_exist(new_move_contract_addr);

                borrow_global_mut<Account>(new_move_contract_addr).nonce = 1;
                borrow_global_mut<Account>(new_move_contract_addr).is_contract = true;
                borrow_global_mut<Account>(new_move_contract_addr).code = run(evm_contract_address, sender, new_evm_contract_addr, new_codes, x"", false, msg_value);

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
                let new_evm_contract_addr = to_32bit(slice(keccak256(p), 12, 20));
                let new_move_contract_addr = create_resource_address(&@aptos_framework, new_evm_contract_addr);
                debug::print(&utf8(b"create2 start"));
                debug::print(&new_evm_contract_addr);
                debug::print(&exists<Account>(new_move_contract_addr));
                assert!(!exist_contract(new_move_contract_addr), CONTRACT_DEPLOYED);
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
                let message = if(vector::length(&bytes) == 0) x"" else {
                    let len = to_u256(slice(bytes, 36, 32));
                    slice(bytes, 68, len)
                };
                debug::print(&bytes);
                // debug::print(&pos);
                // debug::print(&len);
                // debug::print(memory);
                i = i + 1;
                revert(message);
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
            let move_to = create_resource_address(&@aptos_framework, evm_to);
            create_account_if_not_exist(move_to);
            coin::transfer<AptosCoin>(signer, move_to, ((amount / CONVERT_BASE)  as u64));

            let account_store_to = borrow_global_mut<Account>(move_to);
            account_store_to.balance = account_store_to.balance + amount;
        }
    }

    fun transfer_to_evm_addr(evm_from: vector<u8>, evm_to: vector<u8>, amount: u256) acquires Account {
        if(amount > 0) {
            let move_from = create_resource_address(&@aptos_framework, evm_from);
            let move_to = create_resource_address(&@aptos_framework, evm_to);
            create_account_if_not_exist(move_to);
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
            let move_from = create_resource_address(&@aptos_framework, evm_from);
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
            if(!exists_at(addr)) {
                create_account(addr);
            };
            let signer = create_signer(addr);
            coin::register<AptosCoin>(&signer);
            move_to(&signer, Account {
                code: vector::empty(),
                storage: table::new<u256, vector<u8>>(),
                balance: 0,
                is_contract: false,
                nonce: 0
            })
        };
    }

    fun verify_nonce(addr: address, _nonce: u64) acquires Account {
        let coin_store_from = borrow_global_mut<Account>(addr);
        // assert!(coin_store_from.nonce == nonce, NONCE);
        coin_store_from.nonce = coin_store_from.nonce + 1;
    }

    fun verify_signature(from: vector<u8>, message_hash: vector<u8>, r: vector<u8>, s: vector<u8>, v: u64) {
        let input_bytes = r;
        vector::append(&mut input_bytes, s);
        let signature = ecdsa_signature_from_bytes(input_bytes);
        let recovery_id = ((v - (CHAIN_ID * 2) - 35) as u8);
        let pk_recover = ecdsa_recover(message_hash, recovery_id, &signature);
        let pk = keccak256(ecdsa_raw_public_key_to_bytes(borrow(&pk_recover)));
        debug::print(&slice(pk, 12, 20));
        assert!(slice(pk, 12, 20) == from, SIGNATURE);
    }

    #[test]
    fun test_simple_contract() acquires Account, ContractEvent {
        let alice = x"689650fee4c8f9d11ce434695151a4a1f2c42a37";
        let i = 0;
        while(i < 87) {
            let addr = get_contract_address(to_32bit(alice), i);
            debug::print(&addr);
            if(addr == to_32bit(x"116270382e7151059e2628febf3116f14ac3b956")) {
                debug::print(&i);
                break
            };
            i = i + 1;
        };

        let sender = to_32bit(alice);
        let account = create_resource_address(&@aptos_framework, sender);
        create_account_if_not_exist(account);

        let contract1 = x"608060405234801561001057600080fd5b5061001a3361001f565b61008b565b600180546001600160a01b03191690556100388161003b565b50565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b610a1b8061009a6000396000f3fe6080604052600436106100e15760003560e01c8063bce246691161007f578063db1c45f911610059578063db1c45f91461026e578063e30c397814610290578063e87c0ee6146102ae578063f2fde38b146102d157600080fd5b8063bce246691461020e578063cf8d133f1461022e578063d72d04db1461024e57600080fd5b8063715018a6116100bb578063715018a6146101b157806379ba5097146101c65780637f020946146101db5780638da5cb5b146101f057600080fd5b8063155dd5ee1461012257806352897beb146101445780636650e91a1461017957600080fd5b3661011d5760405134815233907f5741979df5f3e491501da74d3b0a83dd2496ab1f34929865b3e190a8ad75859a9060200160405180910390a2005b600080fd5b34801561012e57600080fd5b5061014261013d3660046108d1565b6102f1565b005b34801561015057600080fd5b5061016461015f366004610906565b610352565b60405190151581526020015b60405180910390f35b34801561018557600080fd5b506101996101943660046108d1565b610365565b6040516001600160a01b039091168152602001610170565b3480156101bd57600080fd5b50610142610372565b3480156101d257600080fd5b50610142610386565b3480156101e757600080fd5b50610142610405565b3480156101fc57600080fd5b506000546001600160a01b0316610199565b34801561021a57600080fd5b50610142610229366004610906565b61045d565b34801561023a57600080fd5b50610142610249366004610921565b610470565b34801561025a57600080fd5b50610142610269366004610906565b610533565b34801561027a57600080fd5b50610283610546565b604051610170919061094b565b34801561029c57600080fd5b506001546001600160a01b0316610199565b3480156102ba57600080fd5b506102c3610557565b604051908152602001610170565b3480156102dd57600080fd5b506101426102ec366004610906565b610563565b6102f96105d4565b604051600090339083908381818185875af1925050503d806000811461033b576040519150601f19603f3d011682016040523d82523d6000602084013e610340565b606091505b505090508061034e57600080fd5b5050565b600061035f60028361062e565b92915050565b600061035f600283610653565b61037a6105d4565b610384600061065f565b565b60015433906001600160a01b031681146103f95760405162461bcd60e51b815260206004820152602960248201527f4f776e61626c6532537465703a2063616c6c6572206973206e6f7420746865206044820152683732bb9037bbb732b960b91b60648201526084015b60405180910390fd5b6104028161065f565b50565b61040d6105d4565b60006104196002610678565b905060005b815181101561034e5761045482828151811061043c5761043c610998565b6020026020010151600261068590919063ffffffff16565b5060010161041e565b6104656105d4565b61034e600282610685565b61047b60023361062e565b151560011461048957600080fd5b6000826001600160a01b03168260405160006040518083038185875af1925050503d80600081146104d6576040519150601f19603f3d011682016040523d82523d6000602084013e6104db565b606091505b505060408051338152602081018590529192506001600160a01b038516917fb1da214e79932aa5d0a3c3a3e3260aed98a973ca45f528c6dbbe3c818e3ea4bd910160405180910390a28061052e57600080fd5b505050565b61053b6105d4565b61034e60028261069a565b60606105526002610678565b905090565b600061055260026106af565b61056b6105d4565b600180546001600160a01b0383166001600160a01b0319909116811790915561059c6000546001600160a01b031690565b6001600160a01b03167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e2270060405160405180910390a350565b6000546001600160a01b031633146103845760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657260448201526064016103f0565b6001600160a01b038116600090815260018301602052604081205415155b9392505050565b600061064c83836106b9565b600180546001600160a01b0319169055610402816106e3565b6060600061064c83610733565b600061064c836001600160a01b03841661078f565b600061064c836001600160a01b038416610882565b600061035f825490565b60008260000182815481106106d0576106d0610998565b9060005260206000200154905092915050565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b60608160000180548060200260200160405190810160405280929190818152602001828054801561078357602002820191906000526020600020905b81548152602001906001019080831161076f575b50505050509050919050565b600081815260018301602052604081205480156108785760006107b36001836109ae565b85549091506000906107c7906001906109ae565b905081811461082c5760008660000182815481106107e7576107e7610998565b906000526020600020015490508087600001848154811061080a5761080a610998565b6000918252602080832090910192909255918252600188019052604090208390555b855486908061083d5761083d6109cf565b60019003818190600052602060002001600090559055856001016000868152602001908152602001600020600090556001935050505061035f565b600091505061035f565b60008181526001830160205260408120546108c95750815460018181018455600084815260208082209093018490558454848252828601909352604090209190915561035f565b50600061035f565b6000602082840312156108e357600080fd5b5035919050565b80356001600160a01b038116811461090157600080fd5b919050565b60006020828403121561091857600080fd5b61064c826108ea565b6000806040838503121561093457600080fd5b61093d836108ea565b946020939093013593505050565b6020808252825182820181905260009190848201906040850190845b8181101561098c5783516001600160a01b031683529284019291840191600101610967565b50909695505050505050565b634e487b7160e01b600052603260045260246000fd5b8181038181111561035f57634e487b7160e01b600052601160045260246000fd5b634e487b7160e01b600052603160045260246000fdfea264697066735822122037ef8e5dd0a012ce153c7618a6c8fb31d189aa0ed8b2edf80a52ffaa61cd881764736f6c63430008170033";
        // let addr = execute(sender, to_32bit(x"0000"), 0, contract, 0);
        let contract2 = x"60806040526706f05b59d3b200006007556014600855600a6009819055662386f26fc100009055600d805461ffff191660021790553480156200004157600080fd5b506200004d3362000053565b620000c1565b600180546001600160a01b03191690556200006e8162000071565b50565b600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b61297880620000d16000396000f3fe6080604052600436106102295760003560e01c80637662302211610123578063b497b354116100ab578063ccf1719f1161006f578063ccf1719f146106c8578063d39b5cbb146106de578063d9b61f6814610703578063e30c397814610723578063f2fde38b1461074157600080fd5b8063b497b35414610625578063b4a91e1e1461063b578063c072a4b814610668578063c20ee3fb14610688578063c5f956af146106a857600080fd5b80638da5cb5b116100f25780638da5cb5b146105705780639619367d146105a2578063990d2dbd146105b85780639d4b950c146105e5578063a7f360611461060557600080fd5b8063766230221461048e57806379ba50971461051b5780638824f5a71461053057806388ea41b91461055057600080fd5b80634d23c759116101b15780635c975abb116101755780635c975abb146103ec5780635f1b0fd8146104165780636605bfda1461043957806370cc91ad14610459578063715018a61461047957600080fd5b80634d23c7591461036d578063536a3ddc1461038257806353a2c19a1461039857806353ccbeea146103ac5780635a3e2e8b146103bf57600080fd5b80631fe543e3116101f85780631fe543e3146102b757806321154ec5146102d75780632e35a302146102f7578063398497711461031757806347e1d5501461034057600080fd5b806305287f0c1461023557806316c38b3c146102575780631bdb2d99146102775780631fa33a2a1461029757600080fd5b3661023057005b600080fd5b34801561024157600080fd5b50610255610250366004612124565b610761565b005b34801561026357600080fd5b50610255610272366004612152565b61076e565b34801561028357600080fd5b50610255610292366004612198565b610789565b3480156102a357600080fd5b506102556102b2366004612213565b61087e565b3480156102c357600080fd5b506102556102d2366004612320565b6108b1565b3480156102e357600080fd5b506102556102f2366004612124565b6108fb565b34801561030357600080fd5b50610255610312366004612366565b610908565b34801561032357600080fd5b5061032d60085481565b6040519081526020015b60405180910390f35b34801561034c57600080fd5b5061036061035b366004612124565b610938565b6040516103379190612416565b34801561037957600080fd5b5061032d6109f3565b34801561038e57600080fd5b5061032d60025481565b3480156103a457600080fd5b50600161032d565b61032d6103ba36600461249a565b610a33565b3480156103cb57600080fd5b506103df6103da366004612570565b610f81565b60405161033791906125ac565b3480156103f857600080fd5b506004546104069060ff1681565b6040519015158152602001610337565b34801561042257600080fd5b50600d5460405161ffff9091168152602001610337565b34801561044557600080fd5b50610255610454366004612366565b6110e0565b34801561046557600080fd5b50610255610474366004612124565b61110a565b34801561048557600080fd5b50610255611167565b34801561049a57600080fd5b506105076104a9366004612124565b6003602081905260009182526040909120805460018201546002830154938301546004909301549193909290916001600160a01b039182169181169060ff600160a01b8204811691600160a81b8104821691600160b01b9091041688565b6040516103379897969594939291906125fb565b34801561052757600080fd5b5061025561117b565b34801561053c57600080fd5b5061025561054b366004612655565b6111f5565b34801561055c57600080fd5b5061025561056b366004612124565b611215565b34801561057c57600080fd5b506000546001600160a01b03165b6040516001600160a01b039091168152602001610337565b3480156105ae57600080fd5b5061032d60075481565b3480156105c457600080fd5b506105d86105d3366004612679565b611222565b60405161033791906126af565b3480156105f157600080fd5b50610255610600366004612366565b611265565b34801561061157600080fd5b506102556106203660046126bd565b61128f565b34801561063157600080fd5b5061032d60095481565b34801561064757600080fd5b5061032d610656366004612124565b600e6020526000908152604090205481565b34801561067457600080fd5b50610255610683366004612124565b611316565b34801561069457600080fd5b506102556106a3366004612124565b611323565b3480156106b457600080fd5b5060065461058a906001600160a01b031681565b3480156106d457600080fd5b5061032d600a5481565b3480156106ea57600080fd5b5060045461058a9061010090046001600160a01b031681565b34801561070f57600080fd5b5060055461058a906001600160a01b031681565b34801561072f57600080fd5b506001546001600160a01b031661058a565b34801561074d57600080fd5b5061025561075c366004612366565b611330565b6107696113a1565b600255565b6107766113a1565b6004805460ff1916911515919091179055565b6107916113a1565b6040518060800160405280858152602001846001600160a01b03168152602001836001600160401b031681526020018263ffffffff16815250600c60008760028111156107e0576107e0612383565b60028111156107f1576107f1612383565b815260208082019290925260409081016000208351815591830151600192830180549285015160609095015163ffffffff16600160e01b026001600160e01b036001600160401b03909616600160a01b026001600160e01b03199094166001600160a01b039093169290921792909217939093169290921790915561087790849061087e565b5050505050565b6108866113a1565b6001600160a01b03919091166000908152600b60205260409020805460ff1916911515919091179055565b336000908152600b602052604090205460ff1615156001146108ed57604051637885129b60e01b81523360048201526024015b60405180910390fd5b6108f782826113fb565b5050565b6109036113a1565b600855565b6109106113a1565b600480546001600160a01b0390921661010002610100600160a81b0319909216919091179055565b610940612019565b60008281526003602081815260409283902083516101008101855281548152600182015492810192909252600281015493820193909352828201546001600160a01b0390811660608301526004840154908116608083015260ff600160a01b8204811660a0840152600160a81b8204811660c084015291939260e0850192600160b01b909204909116908111156109d9576109d9612383565b60038111156109ea576109ea612383565b90525092915050565b6008546006546000918291610a1291906001600160a01b03163161270c565b905080605f610a22826064612720565b610a2c919061270c565b9250505090565b6000323314610a7b5760405162461bcd60e51b8152602060048201526014602482015273139bc818dbdb9d1c9858dd1cc8185b1b1bddd95960621b60448201526064016108e4565b60045460ff1615610abf5760405162461bcd60e51b815260206004820152600e60248201526d11d85b59481a5cc81c185d5cd95960921b60448201526064016108e4565b6004805485516006546040805163e54c9f6b60e01b815290516001600160a01b036101009095048516959394600094610b4e949091163192879263e54c9f6b928281019260209291908290030181865afa158015610b21573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b459190612737565b8460ff16611844565b90506000836001600160a01b031663c86210be33896040518363ffffffff1660e01b8152600401610b80929190612750565b602060405180830381865afa158015610b9d573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610bc191906127af565b600280549192506000610bd3836127cc565b9190505550610be0612019565b3360608201526001600160a01b03821660808201526002548152600060e082018190525060ff80851660c083019081526040808601516020808601918252606080890151848801908152600160a0890181815289516000908152600395869052969096208951815594519085015551600284015586015182820180546001600160a01b039283166001600160a01b03199091161790556080870151600484018054955196518816600160a81b0260ff60a81b1997909816600160a01b026001600160a81b03199096169190921617939093179384168517835560e08601518695929490939260ff60b01b191661ffff60a81b199091161790600160b01b908490811115610cef57610cef612383565b02179055505081516000908152600f602090815260409091208b51610d19935090918c019061205b565b5060065483516040516000926001600160a01b031691908381818185875af1925050503d8060008114610d68576040519150601f19603f3d011682016040523d82523d6000602084013e610d6d565b606091505b5050905080610dbe5760405162461bcd60e51b815260206004820152601a60248201527f4661696c656420746f2073656e6420746f20747265617375727900000000000060448201526064016108e4565b506020830151815160405163919ac7ff60e01b815260048101919091523360248201526001600160a01b03848116604483015287169163919ac7ff916064016000604051808303818588803b158015610e1657600080fd5b505af1158015610e2a573d6000803e3d6000fd5b5050835160009081526003602081815260409283902087518155908701516001820155918601516002830155606086015182820180546001600160a01b039283166001600160a01b0319909116179055608087015160048401805460a08a015160c08b015160ff908116600160a81b0260ff60a81b1991909216600160a01b026001600160a81b03199093169490951693909317179283168217815560e089015189985094965093945060ff60b01b191661ffff60a81b199091161790600160b01b908490811115610efe57610efe612383565b02179055509050508060000151336001600160a01b03167f7494146c887905966fa843fa10c09fab62f03193d020a38b6f77631eb79c221c8360a00151878d8660800151876020015188604001518f604051610f6097969594939291906127f5565b60405180910390a38051610f749088611b61565b5198975050505050505050565b80516060906000816001600160401b03811115610fa057610fa0612248565b604051908082528060200260200182016040528015610fd957816020015b610fc6612019565b815260200190600190039081610fbe5790505b50905060005b828110156110d85760036000868381518110610ffd57610ffd612889565b6020908102919091018101518252818101929092526040908101600020815161010081018352815481526001820154938101939093526002810154918301919091526003808201546001600160a01b0390811660608501526004830154908116608085015260ff600160a01b8204811660a0860152600160a81b8204811660c086015260e0850192600160b01b909204169081111561109e5761109e612383565b60038111156110af576110af612383565b815250508282815181106110c5576110c5612889565b6020908102919091010152600101610fdf565b509392505050565b6110e86113a1565b600680546001600160a01b0319166001600160a01b0392909216919091179055565b6111126113a1565b604051600090339083908381818185875af1925050503d8060008114611154576040519150601f19603f3d011682016040523d82523d6000602084013e611159565b606091505b50509050806108f757600080fd5b61116f6113a1565b6111796000611fb5565b565b60015433906001600160a01b031681146111e95760405162461bcd60e51b815260206004820152602960248201527f4f776e61626c6532537465703a2063616c6c6572206973206e6f7420746865206044820152683732bb9037bbb732b960b91b60648201526084016108e4565b6111f281611fb5565b50565b6111fd6113a1565b600d805461ffff191661ffff92909216919091179055565b61121d6113a1565b600755565b600f602052816000526040600020818154811061123e57600080fd5b9060005260206000209060209182820401919006915091509054906101000a900460ff1681565b61126d6113a1565b600580546001600160a01b0319166001600160a01b0392909216919091179055565b6112976113a1565b600082815260036020526040902060016004820154600160b01b900460ff1660038111156112c7576112c7612383565b036113055760405162461bcd60e51b815260206004820152600e60248201526d185b1c9958591e4818db1bdcd95960921b60448201526064016108e4565b80546113119083611b61565b505050565b61131e6113a1565b600955565b61132b6113a1565b600a55565b6113386113a1565b600180546001600160a01b0383166001600160a01b031990911681179091556113696000546001600160a01b031690565b6001600160a01b03167f38d16b8cac22d99fc7c124b9cd0de2d3fa1faef420bfe791d8c362d765e2270060405160405180910390a350565b6000546001600160a01b031633146111795760405162461bcd60e51b815260206004820181905260248201527f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e657260448201526064016108e4565b6000828152600e602090815260408083205480845260038352818420600654600f85528386208054855181880281018801909652808652939692956001600160a01b0390921694929390918301828280156114a557602002820191906000526020600020906000905b82829054906101000a900460ff16600181111561148357611483612383565b8152602060019283018181049485019490930390920291018084116114645790505b505050505090506000815190506000816001600160401b038111156114cc576114cc612248565b60405190808252806020026020018201604052801561152257816020015b61150f6040805160608101909152806000815260200160008152602001600081525090565b8152602001906001900390816114ea5790505b5090506000805b8381101561171f5760008960008151811061154657611546612889565b602002602001015182604051602001611569929190918252602082015260400190565b60408051601f198184030181529190528051602090910120905061158e60028261289f565b1561159a57600161159d565b60005b8483815181106115af576115af612889565b60200260200101516000019060018111156115cc576115cc612383565b908160018111156115df576115df612383565b8152505060018483815181106115f7576115f7612889565b602002602001015160200190600381111561161457611614612383565b9081600381111561162757611627612383565b8152505083828151811061163d5761163d612889565b602002602001015160000151600181111561165a5761165a612383565b86838151811061166c5761166c612889565b6020026020010151600181111561168557611685612383565b0361171657600384838151811061169e5761169e612889565b60200260200101516020019060038111156116bb576116bb612383565b908160038111156116ce576116ce612383565b90525060018801546116e090846128b3565b9250876001015460026116f39190612720565b84838151811061170557611705612889565b602002602001015160400181815250505b50600101611529565b5080156117a85760038601546001600160a01b038087169163cf8d133f9116611749846002612720565b6040516001600160e01b031960e085901b1681526001600160a01b0390921660048301526024820152604401600060405180830381600087803b15801561178f57600080fd5b505af11580156117a3573d6000803e3d6000fd5b505050505b60048601805460ff60b01b1916600160b01b17905560405187907fd19a8beba6d94e6fe6a16804fc461f8a08a13176419a5ceee005d7d48f81366e906117ef9085906128c6565b60405180910390a2505050600093845250506003602081905260408320838155600181018490556002810193909355820180546001600160a01b03191690555060040180546001600160b81b03191690555050565b6118766040518060a0016040528060008152602001600081526020016000815260200160008152602001600081525090565b6000611884846127106128b3565b61189034612710612720565b61189a919061270c565b905060006118a8823461292f565b90506007548210156118f05760405162461bcd60e51b815260206004820152601160248201527023b0b6b136329036b7b9329610383632b160791b60448201526064016108e4565b6008546118fd908761270c565b8211156119405760405162461bcd60e51b815260206004820152601160248201527047616d626c65206c6573732c206b696e6760781b60448201526064016108e4565b600084116119905760405162461bcd60e51b815260206004820152601a60248201527f47616d626c65206174206c65617374206f6e63652c20706c656200000000000060448201526064016108e4565b6009548411156119e25760405162461bcd60e51b815260206004820152601860248201527f47616d626c652066657765722074696d65732c206b696e67000000000000000060448201526064016108e4565b60006119ee858461270c565b90506119fa858461289f565b15611a5d5760405162461bcd60e51b815260206004820152602d60248201527f47616d626c6520616e20616d6f756e7420646976697369626c6520627920796f60448201526c3ab9103132ba399610383632b160991b60648201526084016108e4565b600a54611a6a908261289f565b15611ac55760405162461bcd60e51b815260206004820152602560248201527f47616d626c652074686520726967687420616d6f756e7420706572206265742c60448201526410383632b160d91b60648201526084016108e4565b6000611ad1868461270c565b9050611add868461289f565b15611b345760405162461bcd60e51b815260206004820152602160248201527f496e7465726e616c206572726f723b2077726f6e672072616b6520616d6f756e6044820152601d60fa1b60648201526084016108e4565b6040805160a081018252948552602085019390935291830152606082015260006080820152949350505050565b6000600c6000836002811115611b7957611b79612383565b6002811115611b8a57611b8a612383565b81526020810191909152604001600020600101546001600160a01b0316905080611bec5760405162461bcd60e51b8152602060048201526013602482015272496e76616c696420565246206164647265737360681b60448201526064016108e4565b806002836002811115611c0157611c01612383565b03611d92578160006001600160a01b0382166361b93aa0600c83886002811115611c2d57611c2d612383565b6002811115611c3e57611c3e612383565b815260200190815260200160002060000154600c6000896002811115611c6657611c66612383565b6002811115611c7757611c77612383565b815260200190815260200160002060010160149054906101000a90046001600160401b0316600d60009054906101000a900461ffff16600c60008b6002811115611cc357611cc3612383565b6002811115611cd457611cd4612383565b81526020810191909152604090810160002060019081015491516001600160e01b031960e088901b16815260048101959095526001600160401b03909316602485015261ffff909116604484015263ffffffff600160e01b909104166064830152608482015260a401602060405180830381865afa158015611d5a573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611d7e9190612737565b6000908152600e6020526040902086905550505b6000816001600160a01b0316635d3b1d30600c6000876002811115611db957611db9612383565b6002811115611dca57611dca612383565b815260200190815260200160002060000154600c6000886002811115611df257611df2612383565b6002811115611e0357611e03612383565b815260200190815260200160002060010160149054906101000a90046001600160401b0316600d60009054906101000a900461ffff16600c60008a6002811115611e4f57611e4f612383565b6002811115611e6057611e60612383565b81526020810191909152604090810160002060019081015491516001600160e01b031960e088901b16815260048101959095526001600160401b03909316602485015261ffff909116604484015263ffffffff600160e01b909104166064830152608482015260a4016020604051808303816000875af1158015611ee8573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190611f0c9190612737565b90506002846002811115611f2257611f22612383565b03611f9e576000818152600e60205260409020548514611f9e5760405162461bcd60e51b815260206004820152603160248201527f436f6d70757465642072657175657374494420646964206e6f7420657175616c604482015270081858dd1d585b081c995c5d595cdd1259607a1b60648201526084016108e4565b6000908152600e6020526040902093909355505050565b600180546001600160a01b03191690556111f281600080546001600160a01b038381166001600160a01b0319831681178455604051919092169283917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e09190a35050565b6040805161010081018252600080825260208201819052918101829052606081018290526080810182905260a0810182905260c081018290529060e082015290565b82805482825590600052602060002090601f016020900481019282156120ff5791602002820160005b838211156120d057835183826101000a81548160ff021916908360018111156120af576120af612383565b02179055509260200192600101602081600001049283019260010302612084565b80156120fd5782816101000a81549060ff02191690556001016020816000010492830192600103026120d0565b505b5061210b92915061210f565b5090565b5b8082111561210b5760008155600101612110565b60006020828403121561213657600080fd5b5035919050565b8035801515811461214d57600080fd5b919050565b60006020828403121561216457600080fd5b61216d8261213d565b9392505050565b80356003811061214d57600080fd5b6001600160a01b03811681146111f257600080fd5b600080600080600060a086880312156121b057600080fd5b6121b986612174565b94506020860135935060408601356121d081612183565b925060608601356001600160401b03811681146121ec57600080fd5b9150608086013563ffffffff8116811461220557600080fd5b809150509295509295909350565b6000806040838503121561222657600080fd5b823561223181612183565b915061223f6020840161213d565b90509250929050565b634e487b7160e01b600052604160045260246000fd5b604051601f8201601f191681016001600160401b038111828210171561228657612286612248565b604052919050565b60006001600160401b038211156122a7576122a7612248565b5060051b60200190565b600082601f8301126122c257600080fd5b813560206122d76122d28361228e565b61225e565b8083825260208201915060208460051b8701019350868411156122f957600080fd5b602086015b8481101561231557803583529183019183016122fe565b509695505050505050565b6000806040838503121561233357600080fd5b8235915060208301356001600160401b0381111561235057600080fd5b61235c858286016122b1565b9150509250929050565b60006020828403121561237857600080fd5b813561216d81612183565b634e487b7160e01b600052602160045260246000fd5b600481106111f2576111f2612383565b805182526020810151602083015260408101516040830152606081015160018060a01b038082166060850152806080840151166080850152505060ff60a08201511660a083015260ff60c08201511660c083015260e081015161240b81612399565b8060e0840152505050565b610100810161242582846123a9565b92915050565b600082601f83011261243c57600080fd5b81356001600160401b0381111561245557612455612248565b612468601f8201601f191660200161225e565b81815284602083860101111561247d57600080fd5b816020850160208301376000918101602001919091529392505050565b6000806000606084860312156124af57600080fd5b83356001600160401b03808211156124c657600080fd5b818601915086601f8301126124da57600080fd5b813560206124ea6122d28361228e565b82815260059290921b8401810191818101908a84111561250957600080fd5b948201945b83861015612535578535600281106125265760008081fd5b8252948201949082019061250e565b9750508701359250508082111561254b57600080fd5b506125588682870161242b565b92505061256760408501612174565b90509250925092565b60006020828403121561258257600080fd5b81356001600160401b0381111561259857600080fd5b6125a4848285016122b1565b949350505050565b6020808252825182820181905260009190848201906040850190845b818110156125ef576125db8385516123a9565b9284019261010092909201916001016125c8565b50909695505050505050565b88815260208101889052604081018790526001600160a01b0386811660608301528516608082015260ff84811660a0830152831660c0820152610100810161264283612399565b8260e08301529998505050505050505050565b60006020828403121561266757600080fd5b813561ffff8116811461216d57600080fd5b6000806040838503121561268c57600080fd5b50508035926020909101359150565b600281106126ab576126ab612383565b9052565b60208101612425828461269b565b600080604083850312156126d057600080fd5b8235915061223f60208401612174565b634e487b7160e01b600052601260045260246000fd5b634e487b7160e01b600052601160045260246000fd5b60008261271b5761271b6126e0565b500490565b8082028115828204841417612425576124256126f6565b60006020828403121561274957600080fd5b5051919050565b60018060a01b03831681526000602060406020840152835180604085015260005b8181101561278d57858101830151858201606001528201612771565b506000606082860101526060601f19601f830116850101925050509392505050565b6000602082840312156127c157600080fd5b815161216d81612183565b6000600182016127de576127de6126f6565b5060010190565b600381106126ab576126ab612383565b600060e0820160ff8a168352602060ff8a16602085015260e060408501528189518084526101008601915060208b01935060005b8181101561284c5761283c83865161269b565b9383019391830191600101612829565b50506001600160a01b03891660608601526080850188905260a08501879052925061287d91505060c08301846127e5565b98975050505050505050565b634e487b7160e01b600052603260045260246000fd5b6000826128ae576128ae6126e0565b500690565b80820180821115612425576124256126f6565b602080825282518282018190526000919060409081850190868401855b828110156129225781516128f885825161269b565b8681015161290581612399565b8588015285015185850152606090930192908501906001016128e3565b5091979650505050505050565b81810381811115612425576124256126f656fea2646970667358221220e9ac2526a515f512121e1f800bff9dd4f6dcfc56380393425b8287e5221cf73864736f6c63430008170033";
        let addr1 = execute(sender, ZERO_ADDR, 0, contract1, 0);
        let addr2 = execute(sender, ZERO_ADDR, 17, contract2, 0);

        let call_1_1 = x"9423f0720000000000000000000000003991ce7e803867f9e72f19cd7c6c570a40a597e1";
        execute(sender, addr1, 6, call_1_1, 0);

        // let amount = 10500000000000000000;
        // deposit_to(alice, amount);
        // debug::print(&0);
        // let calldata = x"6605bfda00000000000000000000000058daa362b6732d224a618149c5872b4942947681";
        // execute(sender, addr, 1, calldata, amount);
        // debug::print(&1);
        // let calldata = x"98632b52000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        // execute(sender, addr, 2, calldata, amount);
        // debug::print(&2);
        // let calldata = x"53ccbeea000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        // execute(sender, addr, 3, calldata, amount);
        // debug::print(&3);
    }

    #[test]
    fun test_simple_deploy() acquires Account, ContractEvent {
        let sender = x"054ecb78d0276cf182514211d0c21fe46590b654";
        create_account_if_not_exist(create_resource_address(&@aptos_framework, sender));
        let bytecode_1 = x"6101ca61003a600b82828239805160001a60731461002d57634e487b7160e01b600052600060045260246000fd5b30600052607381538281f3fe73000000000000000000000000000000000000000030146080604052600436106100355760003560e01c806313769cd41461003a575b600080fd5b81801561004657600080fd5b5061005a610055366004610177565b61005c565b005b600c8401546001600160a01b0316156100c75760405162461bcd60e51b8152602060048201526024808201527f526573657276652068617320616c7265616479206265656e20696e697469616c6044820152631a5e995960e21b606482015260840160405180910390fd5b83546000036100e0576b033b2e3c9fd0803ce800000084555b83600701546000036100ff576b033b2e3c9fd0803ce800000060078501555b600c840180546001600160a01b039485166001600160a01b0319909116179055600b840191909155600d909201805460ff60e81b19600168ff000000000000000160a01b03199091169390921692909217600160e01b17169055565b80356001600160a01b038116811461017257600080fd5b919050565b6000806000806080858703121561018d57600080fd5b8435935061019d6020860161015b565b9250604085013591506101b26060860161015b565b90509295919450925056fea164736f6c6343000815000a";
        let addr_1 = execute(sender, ZERO_ADDR, 0, bytecode_1, 0);
        debug::print(&addr_1);

        let bytecode_2 = x"608060405234801561001057600080fd5b5060405161001d906101b6565b604051809103906000f080158015610039573d6000803e3d6000fd5b50600080546001600160a01b0319166001600160a01b03929092169182179055604051610065906101c3565b6001600160a01b039091168152602001604051809103906000f080158015610091573d6000803e3d6000fd5b50600180546001600160a01b0319166001600160a01b039283161790556000546040519116906100c0906101d0565b6001600160a01b039091168152602001604051809103906000f0801580156100ec573d6000803e3d6000fd5b50600280546001600160a01b0319166001600160a01b0392831617905560005460405191169061011b906101dd565b6001600160a01b039091168152602001604051809103906000f080158015610147573d6000803e3d6000fd5b50600380546001600160a01b0319166001600160a01b0392909216919091179055604051610174906101ea565b604051809103906000f080158015610190573d6000803e3d6000fd5b50600480546001600160a01b0319166001600160a01b03929092169190911790556101f7565b6112dc806102f983390190565b611321806115d583390190565b6106ae806128f683390190565b6103c780612fa483390190565b61047b8061336b83390190565b60f4806102056000396000f3fe6080604052348015600f57600080fd5b5060043610605a5760003560e01c80630d7ff88714605f578063406b7eae14608d578063410c3f4c14609f578063a293b0cd1460b1578063a59a99731460c3578063ab5b1dbc1460d5575b600080fd5b6000546071906001600160a01b031681565b6040516001600160a01b03909116815260200160405180910390f35b6004546071906001600160a01b031681565b6002546071906001600160a01b031681565b6005546071906001600160a01b031681565b6003546071906001600160a01b031681565b6001546071906001600160a01b03168156fea164736f6c6343000815000a608060405234801561001057600080fd5b506112bc806100206000396000f3fe60806040526004361061009c5760003560e01c80634fe7a6e5116100645780634fe7a6e514610292578063bcd6ffa4146102b2578063d15e0053146102d2578063e10076ad146102f2578063e240301914610334578063fa51854c1461035457600080fd5b80630902f1ac146100a157806318a4dbca146100cc57806328fcf4d3146100fa57806334b3beee1461010f57806345330a4014610272575b600080fd5b3480156100ad57600080fd5b506100b6610374565b6040516100c39190610f56565b60405180910390f35b3480156100d857600080fd5b506100ec6100e7366004610fb8565b6103d6565b6040519081526020016100c3565b61010d610108366004610ff1565b610462565b005b34801561011b57600080fd5b5061025a61012a366004611032565b6001600160a01b0390811660009081526020818152604091829020825161028081018452815481526001820154928101929092526002810154928201929092526003820154606082015260048201546080820152600582015460a0820152600682015460c0820152600782015460e082015260088201546101008201526009820154610120820152600a820154610140820152600b820154610160820152600c82015483166101808201819052600d909201549283166101a082015264ffffffffff600160a01b8404166101c082015260ff600160c81b8404811615156101e0830152600160d01b840481161515610200830152600160d81b840481161515610220830152600160e01b840481161515610240830152600160e81b90930490921615156102609092019190915290565b6040516001600160a01b0390911681526020016100c3565b34801561027e57600080fd5b5061010d61028d36600461104f565b61063a565b34801561029e57600080fd5b5061025a6102ad3660046110a2565b6106de565b3480156102be57600080fd5b5061010d6102cd3660046110c9565b610708565b3480156102de57600080fd5b506100ec6102ed366004611032565b610747565b3480156102fe57600080fd5b5061031261030d366004610fb8565b61076f565b60408051948552602085019390935291830152151560608201526080016100c3565b34801561034057600080fd5b506100ec61034f366004611032565b61081b565b34801561036057600080fd5b5061010d61036f366004611111565b6108b2565b606060028054806020026020016040519081016040528092919081815260200182805480156103cc57602002820191906000526020600020905b81546001600160a01b031681526001909101906020018083116103ae575b5050505050905090565b6001600160a01b03828116600090815260208190526040808220600c015490516370a0823160e01b815284841660048201529192169081906370a0823190602401602060405180830381865afa158015610434573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610458919061115c565b9150505b92915050565b6001600160a01b03831673eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1461050e5734156104f45760405162461bcd60e51b815260206004820152603260248201527f557365722069732073656e64696e672045544820616c6f6e672077697468207460448201527134329022a9219918103a3930b739b332b91760711b60648201526084015b60405180910390fd5b6105096001600160a01b0384168330846108fd565b505050565b8034101561057c5760405162461bcd60e51b815260206004820152603560248201527f54686520616d6f756e7420616e64207468652076616c75652073656e7420746f604482015274040c8cae0dee6d2e840c8de40dcdee840dac2e8c6d605b1b60648201526084016104eb565b80341115610509576000610590823461118b565b90506000836001600160a01b03168261c35090604051600060405180830381858888f193505050503d80600081146105e4576040519150601f19603f3d011682016040523d82523d6000602084013e6105e9565b606091505b50509050806106335760405162461bcd60e51b8152602060048201526016602482015275151c985b9cd9995c881bd9881155120819985a5b195960521b60448201526064016104eb565b5050505050565b6001600160a01b038481166000908152602081905260409081902090516304dda73560e21b81526004810191909152848216602482015260448101849052908216606482015273d0ad8519b749c7b728478cec66f97d6bce8d3af6906313769cd49060840160006040518083038186803b1580156106b757600080fd5b505af41580156106cb573d6000803e3d6000fd5b505050506106d884610957565b50505050565b600281815481106106ee57600080fd5b6000918252602090912001546001600160a01b0316905081565b6001600160a01b038416600090815260208190526040902061072990610a09565b61073584836000610a9a565b80156106d8576106d8848460016108b2565b6001600160a01b038116600090815260208190526040812061076881610bb0565b9392505050565b6001600160a01b038083166000818152602081815260408083209486168352600182528083209383529290529081209091829182918291826107b189896103d6565b82549091506000036107e3576004909101549095506000945084935060ff650100000000009091041691506108129050565b806107ee8385610be4565b600284015460049094015491985096509194505065010000000000900460ff169150505b92959194509250565b60008073eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeed196001600160a01b0384160161084a57504761045c565b6040516370a0823160e01b81523060048201526001600160a01b038416906370a0823190602401602060405180830381865afa15801561088e573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610768919061115c565b6001600160a01b0391821660009081526001602090815260408083209590941682529390935291206004018054911515650100000000000265ff000000000019909216919091179055565b604080516001600160a01b0385811660248301528416604482015260648082018490528251808303909101815260849091019091526020810180516001600160e01b03166323b872dd60e01b1790526106d8908590610bf7565b6000805b6002548110156109b357826001600160a01b0316600282815481106109825761098261119e565b6000918252602090912001546001600160a01b0316036109a157600191505b806109ab816111b4565b91505061095b565b5080610a0557600280546001810182556000919091527f405787fa12a823e0f2b7631cc41b3ba8828b3321ca811111fa75cd3aa3bb5ace0180546001600160a01b0319166001600160a01b0384161790555b5050565b6000610a1482610c5a565b90508015610a05576001820154600d830154600091610a4091600160a01b900464ffffffffff16610c70565b8354909150610a50908290610cd3565b83556004830154600d840154600091610a7691600160a01b900464ffffffffff16610d17565b9050610a8f846007015482610cd390919063ffffffff16565b600785015550505050565b6001600160a01b038084166000908152602081905260408120600d810154909282918291166357e37af0888789610ad08361081b565b610ada91906111cd565b610ae4919061118b565b6002880154600389015460068a01546040516001600160e01b031960e088901b1681526001600160a01b039095166004860152602485019390935260448401919091526064830152608482015260a401606060405180830381865afa158015610b51573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b7591906111e0565b600187019290925560058601556004850155505050600d01805464ffffffffff60a01b1916600160a01b4264ffffffffff1602179055505050565b6000806107688360000154610bde856001015486600d0160149054906101000a900464ffffffffff16610c70565b90610cd3565b8154600090810361045c5750600061045c565b6000610c0c6001600160a01b03841683610d5f565b90508051600014158015610c31575080806020019051810190610c2f919061120e565b155b1561050957604051635274afe760e01b81526001600160a01b03841660048201526024016104eb565b60008160030154826002015461045c91906111cd565b600080610c8464ffffffffff84164261118b565b90506000610ca7610c986301e13380610d6d565b610ca184610d6d565b90610d7d565b90506b033b2e3c9fd0803ce8000000610cc08683610cd3565b610cca91906111cd565b95945050505050565b60006b033b2e3c9fd0803ce8000000610cec838561122b565b610d0360026b033b2e3c9fd0803ce8000000611258565b610d0d91906111cd565b6107689190611258565b600080610d2b64ffffffffff84164261118b565b90506000610d3d6301e1338086611258565b9050610cca82610d596b033b2e3c9fd0803ce8000000846111cd565b90610db8565b606061076883836000610e31565b600061045c633b9aca008361122b565b600080610d8b600284611258565b905082610da46b033b2e3c9fd0803ce80000008661122b565b610dae90836111cd565b6104589190611258565b6000610dc560028361126c565b600003610dde576b033b2e3c9fd0803ce8000000610de0565b825b9050610ded600283611258565b91505b811561045c57610e008384610cd3565b9250610e0d60028361126c565b15610e1f57610e1c8184610cd3565b90505b610e2a600283611258565b9150610df0565b606081471015610e565760405163cd78605960e01b81523060048201526024016104eb565b600080856001600160a01b03168486604051610e729190611280565b60006040518083038185875af1925050503d8060008114610eaf576040519150601f19603f3d011682016040523d82523d6000602084013e610eb4565b606091505b5091509150610ec4868383610ece565b9695505050505050565b606082610ee357610ede82610f2a565b610768565b8151158015610efa57506001600160a01b0384163b155b15610f2357604051639996b31560e01b81526001600160a01b03851660048201526024016104eb565b5080610768565b805115610f3a5780518082602001fd5b604051630a12f52160e11b815260040160405180910390fd5b50565b6020808252825182820181905260009190848201906040850190845b81811015610f975783516001600160a01b031683529284019291840191600101610f72565b50909695505050505050565b6001600160a01b0381168114610f5357600080fd5b60008060408385031215610fcb57600080fd5b8235610fd681610fa3565b91506020830135610fe681610fa3565b809150509250929050565b60008060006060848603121561100657600080fd5b833561101181610fa3565b9250602084013561102181610fa3565b929592945050506040919091013590565b60006020828403121561104457600080fd5b813561076881610fa3565b6000806000806080858703121561106557600080fd5b843561107081610f";
        let addr_2 = execute(sender, ZERO_ADDR, 1, bytecode_2, 0);
        debug::print(&addr_2);
    }

    #[test_only]
    fun deposit_to(addr: vector<u8>, amount: u256) acquires Account {
        let evm = account::create_account_for_test(@0x1);
        let (burn_cap, freeze_cap, mint_cap) = coin::initialize<AptosCoin>(
            &evm,
            string::utf8(b"APT"),
            string::utf8(b"APT"),
            8,
            false,
        );
        let to = account::create_account_for_test(@0xc5cb1f1ce6951226e9c46ce8d42eda1ac9774a0fef91e2910939119ef0c95568);
        let coins = coin::mint<AptosCoin>(((amount / CONVERT_BASE) as u64), &mint_cap);
        coin::register<AptosCoin>(&to);
        coin::register<AptosCoin>(&evm);
        coin::deposit(@aptos_framework, coins);

        deposit(&evm, addr, u256_to_data(amount));
        coin::destroy_freeze_cap(freeze_cap);
        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(evm = @0x2)]
    fun test_deposit_withdraw() acquires Account {

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
