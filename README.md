## Movement Subnet
Currently deployed on the Avalanche Fuji network, you can access it through the following command

#### Create Account
```bash
curl -X POST --data '{
  "jsonrpc": "2.0",
  "id"     : 1,
  "method" : "createAccount",
  "params" : [{"data":"0xd91cd0f918bcf87fa5b1969dbe21af5973de6abbc1eced010f866e4a19dbeeca"}]
}' -H 'content-type:application/json;' https://move-v2.bbd.sh/rpc/ext/bc/2vUTKYZBbLtXnfCL2RF5XEChZf1wxVYQqxZQQCShMmseSKSiee/rpc 

```

#### Faucet Native Token
```bash
curl -X POST --data '{
  "jsonrpc": "2.0",
  "id"     : 1,
  "method" : "faucet",
  "params" : [{"data":"b3e5e9d58797efbce688894c9aebf09afb074d9c03201b452bc81e8afcd4a75d"}]
}' -H 'content-type:application/json;' https://move-v2.bbd.sh/rpc/ext/bc/2vUTKYZBbLtXnfCL2RF5XEChZf1wxVYQqxZQQCShMmseSKSiee/rpc


```

#### Get Tx Receipt
```bash
curl -X POST --data '{
  "jsonrpc": "2.0",
  "id"     : 1,
  "method" : "getTransactionByHash",
  "params" : [{"data":"1f073fce3c2390d68a95289dc81df9dad1d0fa07541da5da4e1b46241f4bd24e"}]
}' -H 'content-type:application/json;' https://move-v2.bbd.sh/rpc/ext/bc/2vUTKYZBbLtXnfCL2RF5XEChZf1wxVYQqxZQQCShMmseSKSiee/rpc 


```
