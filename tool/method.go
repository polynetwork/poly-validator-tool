package tool

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/Zilliqa/gozilliqa-sdk/core"
	"github.com/Zilliqa/gozilliqa-sdk/provider"
	poly_go_sdk "github.com/polynetwork/poly-go-sdk"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	poly_go_sdk_utils "github.com/polynetwork/poly-go-sdk/utils"
	"github.com/polynetwork/poly-validator-tool/log"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	"github.com/polynetwork/poly/native/service/governance/node_manager"
	"github.com/polynetwork/poly/native/service/utils"
)

type PeerParam struct {
	PeerPubkey string
	Path       string
}

func RegisterCandidate(t *Tool) error {
	data, err := ioutil.ReadFile("./params/RegisterCandidate.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	registerPeerParam := new(PeerParam)
	err = json.Unmarshal(data, registerPeerParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	time.Sleep(1 * time.Second)
	user, err := getAccountByPassword(t, registerPeerParam.Path)
	if err != nil {
		return err
	}
	txHash, err := t.sdk.Native.Nm.RegisterCandidate(registerPeerParam.PeerPubkey, user)
	if err != nil {
		return fmt.Errorf("ctx.Ont.Native.Nm.RegisterCandidate error: %v", err)
	}
	log.Infof("RegisterCandidate txHash is: %v", txHash.ToHexString())
	err = waitForBlock(t)
	if err != nil {
		return fmt.Errorf("waitForBlock failed: %s", err)
	}
	return nil
}

func ApproveCandidate(t *Tool) error {
	data, err := ioutil.ReadFile("./params/ApproveCandidate.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	peerParam := new(PeerParam)
	err = json.Unmarshal(data, peerParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	time.Sleep(1 * time.Second)
	user, err := getAccountByPassword(t, peerParam.Path)
	if err != nil {
		return err
	}
	txHash, err := t.sdk.Native.Nm.ApproveCandidate(peerParam.PeerPubkey, user)
	if err != nil {
		return fmt.Errorf("ctx.Ont.Native.Nm.ApproveCandidate error: %v", err)
	}
	log.Infof("ApproveCandidate txHash is: %v", txHash.ToHexString())
	err = waitForBlock(t)
	if err != nil {
		return fmt.Errorf("waitForBlock failed: %s", err)
	}
	return nil
}

func QuitNode(t *Tool) error {
	data, err := ioutil.ReadFile("./params/QuitNode.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	peerParam := new(PeerParam)
	err = json.Unmarshal(data, peerParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	time.Sleep(1 * time.Second)
	user, err := getAccountByPassword(t, peerParam.Path)
	if err != nil {
		return err
	}
	txHash, err := t.sdk.Native.Nm.QuitNode(peerParam.PeerPubkey, user)
	if err != nil {
		return fmt.Errorf("ctx.Ont.Native.Nm.QuitNode error: %v", err)
	}
	log.Infof("QuitNode txHash is: %v", txHash.ToHexString())
	err = waitForBlock(t)
	if err != nil {
		return fmt.Errorf("waitForBlock failed: %s", err)
	}
	return nil
}

type GenCommitDposTxParam struct {
	Pubkeys []string
	M       uint16
	Path    string
}

func GenCommitDposTx(t *Tool) error {
	data, err := ioutil.ReadFile("./params/GenCommitDposTx.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	genCommitDposTxParam := new(GenCommitDposTxParam)
	err = json.Unmarshal(data, genCommitDposTxParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	time.Sleep(1 * time.Second)
	user, err := getAccountByPassword(t, genCommitDposTxParam.Path)
	if err != nil {
		return err
	}

	pubKeys := make([]keypair.PublicKey, 0)
	for _, s := range genCommitDposTxParam.Pubkeys {
		sBytes, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("hex.DecodeString error:%s", err)
		}
		pk, err := keypair.DeserializePublicKey(sBytes)
		if err != nil {
			return fmt.Errorf("keypair.DeserializePublicKey error:%s", err)
		}
		pubKeys = append(pubKeys, pk)
	}

	method := node_manager.COMMIT_DPOS
	contractAddress := utils.NodeManagerContractAddress
	tx, err := t.sdk.Native.NewNativeInvokeTransaction(byte(0), contractAddress, method, []byte{})
	if err != nil {
		return fmt.Errorf("NewNativeInvokeTransaction error: %s", err)
	}
	err = t.sdk.MultiSignToTransaction(tx, genCommitDposTxParam.M, pubKeys, user)
	if err != nil {
		return fmt.Errorf("MultiSignToTransaction error: %s", err)
	}
	log.Infof("commit dpos tx with self sign is: %s", hex.EncodeToString(tx.ToArray()))
	return nil
}

type MultiSignParam struct {
	RawTx   string
	Pubkeys []string
	M       uint16
	Path    string
}

func MultiSign(t *Tool) error {
	data, err := ioutil.ReadFile("./params/MultiSign.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	multiSignParam := new(MultiSignParam)
	err = json.Unmarshal(data, multiSignParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	time.Sleep(1 * time.Second)
	user, err := getAccountByPassword(t, multiSignParam.Path)
	if err != nil {
		return err
	}

	pubKeys := make([]keypair.PublicKey, 0)
	for _, s := range multiSignParam.Pubkeys {
		sBytes, err := hex.DecodeString(s)
		if err != nil {
			return fmt.Errorf("hex.DecodeString error:%s", err)
		}
		pk, err := keypair.DeserializePublicKey(sBytes)
		if err != nil {
			return fmt.Errorf("keypair.DeserializePublicKey error:%s", err)
		}
		pubKeys = append(pubKeys, pk)
	}

	raw, err := hex.DecodeString(multiSignParam.RawTx)
	if err != nil {
		return fmt.Errorf("hex.DecodeString error: %s", err)
	}
	tx, err := types.TransactionFromRawBytes(raw)
	if err != nil {
		return fmt.Errorf("types.TransactionFromRawBytes error: %s", err)
	}
	err = t.sdk.MultiSignToTransaction(tx, multiSignParam.M, pubKeys, user)
	if err != nil {
		return fmt.Errorf("MultiSignToTransaction error: %s", err)
	}
	log.Infof("commit dpos tx with self sign is: %s", hex.EncodeToString(tx.ToArray()))
	return nil
}

type SendTxParam struct {
	RawTx string
}

func SendTx(t *Tool) error {
	data, err := ioutil.ReadFile("./params/SendTx.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	sendTxParam := new(SendTxParam)
	err = json.Unmarshal(data, sendTxParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}
	raw, err := hex.DecodeString(sendTxParam.RawTx)
	if err != nil {
		return fmt.Errorf("hex.DecodeString error: %s", err)
	}
	tx, err := types.TransactionFromRawBytes(raw)
	if err != nil {
		return fmt.Errorf("types.TransactionFromRawBytes error: %s", err)
	}

	hash, err := t.sdk.SendTransaction(tx)
	if err != nil {
		return fmt.Errorf("t.sdk.SendTransaction error: %s", err)
	}
	log.Infof("tx hash is: %s", hash.ToHexString())

	return nil
}

type RegisterWhiteListParam struct {
	AddressList []string
	Path        string
}

func RegisterWhiteList(t *Tool) error {
	data, err := ioutil.ReadFile("./params/RegisterWhiteList.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	registerWhiteListParam := new(RegisterWhiteListParam)
	err = json.Unmarshal(data, registerWhiteListParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	addressList := make([]common.Address, 0)
	for _, addr := range registerWhiteListParam.AddressList {
		address, err := common.AddressFromBase58(addr)
		if err != nil {
			return fmt.Errorf("common.AddressFromBase58 failed %v", err)
		}
		addressList = append(addressList, address)
	}

	user, err := getAccountByPassword(t, registerWhiteListParam.Path)
	if err != nil {
		return err
	}
	txHash, err := t.sdk.Native.Rm.RegisterRelayer(addressList, user)
	if err != nil {
		return fmt.Errorf("ctx.Ont.Native.Rm.RegisterRelayer error: %v", err)
	}
	log.Infof("RegisterWhiteList txHash is: %v", txHash.ToHexString())
	waitForBlock(t)
	return nil
}

type ApproveWhiteListParam struct {
	ID   uint64
	Path string
}

func ApproveWhiteList(t *Tool) error {
	data, err := ioutil.ReadFile("./params/ApproveWhiteList.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	approveWhiteListParam := new(ApproveWhiteListParam)
	err = json.Unmarshal(data, approveWhiteListParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	user, err := getAccountByPassword(t, approveWhiteListParam.Path)
	if err != nil {
		return err
	}
	txHash, err := t.sdk.Native.Rm.ApproveRegisterRelayer(approveWhiteListParam.ID, user)
	if err != nil {
		return fmt.Errorf("ctx.Ont.Native.Rm.RegisterRelayer error: %v", err)
	}
	log.Infof("ApproveWhiteList txHash is: %v", txHash.ToHexString())
	waitForBlock(t)
	return nil
}

func GetPeerPoolMap(t *Tool) error {
	contractAddress := utils.NodeManagerContractAddress
	governanceView, err := getGovernanceView(t)
	if err != nil {
		return fmt.Errorf("getGovernanceView error: %s", err)
	}
	peerPoolMap := &node_manager.PeerPoolMap{
		PeerPoolMap: make(map[string]*node_manager.PeerPoolItem),
	}
	viewBytes := utils.GetUint32Bytes(governanceView.View)
	key := ConcatKey([]byte(node_manager.PEER_POOL), viewBytes)
	value, err := t.sdk.GetStorage(contractAddress.ToHexString(), key)
	if err != nil {
		return fmt.Errorf("getStorage error")
	}
	if err := peerPoolMap.Deserialization(common.NewZeroCopySource(value)); err != nil {
		return fmt.Errorf("deserialize, deserialize peerPoolMap error")
	}
	for _, v := range peerPoolMap.PeerPoolMap {
		fmt.Println("###########################################")
		fmt.Println("Index is:", v.Index)
		fmt.Println("PeerPubkey is:", v.PeerPubkey)
		fmt.Println("Address is:", v.Address.ToBase58())
		fmt.Println("Status is:", v.Status)
	}
	return nil
}

func GetGovernanceView(t *Tool) error {
	governanceView, err := getGovernanceView(t)
	if err != nil {
		return fmt.Errorf("getGovernanceView failed %v", err)
	}
	fmt.Println("governanceView.View is:", governanceView.View)
	fmt.Println("governanceView.TxHash is:", governanceView.TxHash.ToHexString())
	fmt.Println("governanceView.Height is:", governanceView.Height)
	return nil
}

func getGovernanceView(t *Tool) (*node_manager.GovernanceView, error) {
	contractAddress := utils.NodeManagerContractAddress
	governanceView := new(node_manager.GovernanceView)
	key := []byte(node_manager.GOVERNANCE_VIEW)
	value, err := t.sdk.GetStorage(contractAddress.ToHexString(), key)
	if err != nil {
		return nil, fmt.Errorf("getStorage error: %s", err)
	}
	if err := governanceView.Deserialization(common.NewZeroCopySource(value)); err != nil {
		return nil, fmt.Errorf("deserialize, deserialize governanceView error: %s", err)
	}
	return governanceView, nil
}

type SideChainParam struct {
	Path         string
	Chainid      uint64
	Router       uint64
	Name         string
	BlocksToWait uint64
	CCMCAddress  string
	Extra        string
}

func RegisterSideChain(t *Tool) error {
	data, err := ioutil.ReadFile("./params/RegisterSideChain.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	sideChainParam := new(SideChainParam)
	err = json.Unmarshal(data, sideChainParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	user, err := getAccountByPassword(t, sideChainParam.Path)
	if err != nil {
		return err
	}
	CCMCAddress, err := hex.DecodeString(strings.ToLower(strings.TrimPrefix(sideChainParam.CCMCAddress, "0x")))
	if err != nil {
		return fmt.Errorf("hex.DecodeString error %v", err)
	}
	txHash, err := t.sdk.Native.Scm.RegisterSideChainExt(user.Address, sideChainParam.Chainid,
		sideChainParam.Router, sideChainParam.Name, sideChainParam.BlocksToWait,
		CCMCAddress, []byte(sideChainParam.Extra), user)
	if err != nil {
		return fmt.Errorf("t.sdk.Native.Scm.RegisterSideChain error: %v", err)
	}
	fmt.Printf("RegisterSideChain txHash is: %v\n", txHash.ToHexString())
	waitForBlock(t)
	return nil
}

type ApproveSideChainParam struct {
	Path    []string
	Chainid uint64
}

func ApproveRegisterSideChain(t *Tool) error {
	data, err := ioutil.ReadFile("./params/ApproveRegisterSideChain.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	approveSideChainParam := new(ApproveSideChainParam)
	err = json.Unmarshal(data, approveSideChainParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	time.Sleep(1 * time.Second)
	for _, path := range approveSideChainParam.Path {
		user, err := getAccountByPassword(t, path)
		if err != nil {
			return err
		}
		txHash, err := t.sdk.Native.Scm.ApproveRegisterSideChain(approveSideChainParam.Chainid, user)
		if err != nil {
			return fmt.Errorf("t.sdk.Native.Scm.ApproveRegisterSideChain error: %v", err)
		}
		fmt.Printf("ApproveRegisterSideChain txHash is: %v\n", txHash.ToHexString())
	}
	waitForBlock(t)
	return nil
}

func ApproveUpdateSideChain(t *Tool) error {
	data, err := ioutil.ReadFile("./params/ApproveUpdateSideChain.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	approveSideChainParam := new(ApproveSideChainParam)
	err = json.Unmarshal(data, approveSideChainParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}

	time.Sleep(1 * time.Second)
	for _, path := range approveSideChainParam.Path {
		user, err := getAccountByPassword(t, path)
		if err != nil {
			return err
		}
		txHash, err := t.sdk.Native.Scm.ApproveUpdateSideChain(approveSideChainParam.Chainid, user)
		if err != nil {
			return fmt.Errorf("ctx.Ont.Native.Scm.ApproveUpdateSideChain error: %v", err)
		}
		fmt.Printf("ApproveUpdateSideChain txHash is: %v\n", txHash.ToHexString())
	}
	waitForBlock(t)
	return nil
}

type GetZilGenesisHeaderParam struct {
	ZilliqaRPC     string
	ZilliqaChainId uint64
}

func GetZilGenesisHeader(t *Tool) error {
	data, err := ioutil.ReadFile("./params/GetZilGenesisHeader.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	getZilGenesisHeaderParam := new(GetZilGenesisHeaderParam)
	err = json.Unmarshal(data, getZilGenesisHeaderParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}
	type TxBlockAndDsComm struct {
		TxBlock *core.TxBlock
		DsBlock *core.DsBlock
		DsComm  []core.PairOfNode
	}

	zilSdk := provider.NewProvider(getZilGenesisHeaderParam.ZilliqaRPC)
	// ON TESTNET it gets the currentDScomm. The getMiner info returns the an empty dscommittee
	// for a previous DSBlock num
	initDsComm, err := zilSdk.GetCurrentDSComm()
	if err != nil {
		return fmt.Errorf("zilSdk.GetCurrentDSComm failed: %v", err)
	}
	// as its name suggest, the tx epoch is actually a future tx block
	// zilliqa side has this limitation to avoid some risk that no tx block got mined yet
	nextTxEpoch, err := strconv.ParseUint(initDsComm.CurrentTxEpoch, 10, 64)
	if err != nil {
		return fmt.Errorf("strconv.ParseUintm failed: %v", err)
	}
	fmt.Printf("next tx epoch is %v, current tx block number is %s, ds block number is %s, number of ds guard is: %d\n", nextTxEpoch, initDsComm.CurrentTxEpoch, initDsComm.CurrentDSEpoch, initDsComm.NumOfDSGuard)

	for {
		latestTxBlock, err := zilSdk.GetLatestTxBlock()
		if err != nil {
			return fmt.Errorf("zilSdk.GetLatestTxBlock failed: %v", err)
		}
		fmt.Println("wait current tx block got generated")
		latestTxBlockNum, err := strconv.ParseUint(latestTxBlock.Header.BlockNum, 10, 64)
		if err != nil {
			return fmt.Errorf("strconv.ParseUint BlockNum failed: %v", err)
		}
		fmt.Printf("latest tx block num is: %d, next tx epoch num is: %d\n", latestTxBlockNum, nextTxEpoch)
		if latestTxBlockNum >= nextTxEpoch {
			break
		}
		time.Sleep(time.Second * 20)
	}

	var dsComm []core.PairOfNode
	for _, ds := range initDsComm.DSComm {
		dsComm = append(dsComm, core.PairOfNode{
			PubKey: ds,
		})
	}
	dsBlockT, err := zilSdk.GetDsBlockVerbose(initDsComm.CurrentDSEpoch)
	if err != nil {
		return fmt.Errorf("zilSdk.GetDsBlockVerbose get ds block %s failed: %v", initDsComm.CurrentDSEpoch, err)
	}
	dsBlock := core.NewDsBlockFromDsBlockT(dsBlockT)
	txBlockT, err := zilSdk.GetTxBlockVerbose(initDsComm.CurrentTxEpoch)
	if err != nil {
		return fmt.Errorf("zilSdk.GetTxBlockVerbose get tx block %s failed: %v", initDsComm.CurrentTxEpoch, err)
	}

	txBlock := core.NewTxBlockFromTxBlockT(txBlockT)

	txBlockAndDsComm := TxBlockAndDsComm{
		TxBlock: txBlock,
		DsBlock: dsBlock,
		DsComm:  dsComm,
	}

	raw, err := json.Marshal(txBlockAndDsComm)
	if err != nil {
		return fmt.Errorf("json.Marshal txBlockAndDsComm failed: %v", err)
	}
	tx, err := t.sdk.Native.Hs.NewSyncGenesisHeaderTransaction(getZilGenesisHeaderParam.ZilliqaChainId, raw)
	if err != nil {
		return fmt.Errorf("NewSyncGenesisHeaderTransaction failed: %v", err)
	}
	txString := hex.EncodeToString(tx.ToArray())
	if err != nil {
		return fmt.Errorf("hex.DecodeString sink error: %v", err)
	}
	file, err := os.OpenFile("sigDataIn.txt", os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("open file sigDataIn.txt err: %v", err)
	}
	defer file.Close()

	_, err = file.Write([]byte(txString))
	if err != nil {
		return fmt.Errorf("write file sigDataIn.txt err: %v", err)
	}
	fmt.Println("success GetZilGenesisHeader, write sigDataIn.txt")
	return nil
}

type SignatureDataParam struct {
	Path      string
	SigDataIn string
	SigM      uint16
}

func SignatureData(t *Tool) error {
	data, err := ioutil.ReadFile("./params/SignatureData.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	signatureDataParam := new(SignatureDataParam)
	err = json.Unmarshal(data, signatureDataParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal signatureDataParam failed %v", err)
	}
	tx, err := poly_go_sdk_utils.TransactionFromHexString(signatureDataParam.SigDataIn)
	if err != nil {
		return fmt.Errorf("poly_go_sdk_utils.TransactionFromHexString failed %v", err)
	}
	user, err := getAccountByPassword(t, signatureDataParam.Path)
	if err != nil {
		return fmt.Errorf("getAccountByPassword failed %v", err)
	}
	pubKeys := make([]keypair.PublicKey, 0)
	pubKeys = append(pubKeys, user.PublicKey)
	fmt.Println(user.Address.ToHexString())
	err = SignMToTransaction(tx, signatureDataParam.SigM, pubKeys, user)
	if err != nil {
		return fmt.Errorf("SignMToTransaction failed, err: %s", err)
	}
	txString := hex.EncodeToString(tx.ToArray())
	if err != nil {
		return fmt.Errorf("hex.DecodeString sink error: %v", err)
	}
	file, err := os.OpenFile("sigDataOut.txt", os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("open file sigDataOut.txt err: %v", err)
	}
	defer file.Close()

	_, err = file.Write([]byte(txString))
	if err != nil {
		return fmt.Errorf("write file sigDataOut.txt err: %v", err)
	}
	fmt.Println("success SignatureData, write sigDataOut.txt")
	return nil
}

func SignMToTransaction(tx *types.Transaction, m uint16, pubKeys []keypair.PublicKey, signer *poly_go_sdk.Account) error {
	fmt.Println(len(tx.Sigs))
	validPubKey := false
	for _, pk := range pubKeys {
		if keypair.ComparePublicKey(pk, signer.GetPublicKey()) {
			validPubKey = true
			break
		}
	}
	if !validPubKey {
		return fmt.Errorf("invalid signer")
	}
	txHash := tx.Hash()
	if len(tx.Sigs) == 0 {
		tx.Sigs = make([]types.Sig, 0)
	}
	sigData, err := signer.Sign(txHash.ToArray())
	if err != nil {
		return fmt.Errorf("sign error:%s", err)
	}
	hasMutilSig := false
	for i, sigs := range tx.Sigs {
		if poly_go_sdk_utils.PubKeysEqual(sigs.PubKeys, pubKeys) {
			hasMutilSig = true
			if poly_go_sdk_utils.HasAlreadySig(txHash.ToArray(), signer.GetPublicKey(), sigs.SigData) {
				break
			}
			sigs.SigData = append(sigs.SigData, sigData)
			tx.Sigs[i] = sigs
			break
		}
	}
	if !hasMutilSig {
		tx.Sigs = append(tx.Sigs, types.Sig{
			PubKeys: pubKeys,
			M:       m,
			SigData: [][]byte{sigData},
		})
	}
	return nil
}

type SyncZilGenesisHeaderParam struct {
	Tx string
}

func SyncZilGenesisHeader(t *Tool) error {
	data, err := ioutil.ReadFile("./params/SyncZilGenesisHeader.json")
	if err != nil {
		return fmt.Errorf("ioutil.ReadFile failed %v", err)
	}
	syncZilGenesisHeaderParam := new(SyncZilGenesisHeaderParam)
	err = json.Unmarshal(data, syncZilGenesisHeaderParam)
	if err != nil {
		return fmt.Errorf("json.Unmarshal failed %v", err)
	}
	tx, err := poly_go_sdk_utils.TransactionFromHexString(syncZilGenesisHeaderParam.Tx)
	if err != nil {
		return fmt.Errorf("poly_go_sdk_utils.TransactionFromHexString failed %v", err)
	}
	txhash, err := t.sdk.SendTransaction(tx)
	if err != nil {
		return fmt.Errorf("t.sdk.SendTransaction failed %v", err)
	}
	fmt.Println("success send tx hash:", txhash.ToHexString())
	return nil
}
