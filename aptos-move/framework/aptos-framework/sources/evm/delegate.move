module aptos_framework::delegate {
    use aptos_framework::evm_util::{slice, to_u256};
    use aptos_framework::multisig_account::vote_transanction;
    use aptos_std::from_bcs::to_address;
    friend aptos_framework::evm;

    public(friend) fun execute_move_tx(signer: &signer, _to: address, data: vector<u8>) {

        let selector = slice(data, 0, 4);
        if(selector == x"10d6791e") {
            let multisig_address = to_address(slice(data, 4, 32));
            let sequence_number = to_u256(slice(data, 36, 32));
            let approved = if(to_u256(slice(data, 68, 32)) == 1) true else false;
            vote_transanction(signer, multisig_address, (sequence_number as u64), approved);
        }
    }
}

