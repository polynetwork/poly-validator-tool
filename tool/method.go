package tool

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
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
