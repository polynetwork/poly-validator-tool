# poly-validator-tool

## Use poly binary to generate 2 new poly account, command is:
./poly account add -d --w wallet.dat
We use wallet_validator.dat as validator account, use wallet_auth.dat as the auth account, and wallet_old.dat as the old validator account.

## Pull poly-validator-tool repo:
https://github.com/polynetwork/poly-validator-tool
, and edit config file: config.json to mainnet rpc endpoint.(http://seed1.poly.network:20336), then run command:
```shell
make build
```

## RegisterCandidate
Edit config file in ./params/RegisterCandidate.json, PeerPubkey is the public key of wallet_validator.dat, and Path is the path of wallet_auth.dat, then run command:
```shell
./poly-validator-tool -m RegisterCandidate
```
and input password of wallet_auth.dat.

## ApproveCandidate
Edit config file in ./params/ApproveCandidate.json, PeerPubkey is the public key of wallet_validator.dat, and Path is the path of wallet_old.dat, then run command:
```shell
./poly-validator-tool -m ApproveCandidate
```
and input password of wallet_old.dat.

## QuitNode
Edit config file in ./params/ApproveCandidate.json, PeerPubkey is the public key of wallet_old.dat, and Path is the path of wallet_old.dat, then run command:
```shell
./poly-validator-tool -m QuitNode
```
and input password of wallet_old.dat.

## MultiSign
We will send you a raw tx in hex string format, then you need to edit config file in 
 ./params/CommitDpos, RawTx is the hex string we send to you, PubKeys is the public key list of 4 validators, M is 3, and Path is the path of wallet_old.dat, then run command:
```shell
./poly-validator-tool -m MultiSign
```
and input password of wallet_old.dat.
Next send the output string in std-out to us.

## RegisterSideChain
Edit config file in ./params/RegisterSideChain.json, Path is the path of wallet_auth.dat, Chainid is chainId of RegisterSideChain, Router is 0 (voter), Name is chain name, BlocksToWait is 1, CCMCAddress is chain CCM, Extra is nil, then run command:
```shell
./poly-validator-tool -m RegisterSideChain
```
and input password of wallet_auth.dat.

## ApproveRegisterSideChain
Edit config file in ./params/ApproveRegisterSideChain.json, Path is the path of wallet_old.dat, Chainid is chainId of ApproveRegisterSideChain, then run command:
```shell
./poly-validator-tool -m ApproveRegisterSideChain
```
and input password of wallet_old.dat.

## ApproveUpdateSideChain
Edit config file in ./params/ApproveUpdateSideChain.json, Path is the path of wallet_old.dat, Chainid is chainId of ApproveUpdateSideChain, then run command:
```shell
./poly-validator-tool -m ApproveUpdateSideChain
```
and input password of wallet_old.dat.
