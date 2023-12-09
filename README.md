## Movement Subnet
Currently deployed on the Avalanche Fuji network, you can access it through the following command

#### Create Account With Address
> address with prefix 0x
```bash
curl -X POST --data '{
  "jsonrpc": "2.0",
  "id"     : 1,
  "method" : "createAccount",
  "params" : [{"data":"0xb3e5e9d58797efbce688894c9aebf09afb074d9c03201b452bc81e8afcd4a75d"}]
}' -H 'content-type:application/json;'  https://move-v2.bbd.sh/ext/bc/2vUTKYZBbLtXnfCL2RF5XEChZf1wxVYQqxZQQCShMmseSKSiee/rpc 

```

#### Faucet Native Token With Address
> You must create the account firstly, address without prefix 0x
```bash
curl -X POST --data '{
  "jsonrpc": "2.0",
  "id"     : 1,
  "method" : "faucet",
  "params" : [{"data":"b3e5e9d58797efbce688894c9aebf09afb074d9c03201b452bc81e8afcd4a75d"}]
}' -H 'content-type:application/json;'   https://move-v2.bbd.sh/ext/bc/2vUTKYZBbLtXnfCL2RF5XEChZf1wxVYQqxZQQCShMmseSKSiee/rpc


```

#### Get Tx Receipt
```bash
curl -X POST --data '{
  "jsonrpc": "2.0",
  "id"     : 1,
  "method" : "getTransactionByHash",
  "params" : [{"data":"1f073fce3c2390d68a95289dc81df9dad1d0fa07541da5da4e1b46241f4bd24e"}]
}' -H 'content-type:application/json;'  https://move-v2.bbd.sh/ext/bc/2vUTKYZBbLtXnfCL2RF5XEChZf1wxVYQqxZQQCShMmseSKSiee/rpc 


```
