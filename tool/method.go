package tool

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/polynetwork/poly-validator-tool/log"
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
