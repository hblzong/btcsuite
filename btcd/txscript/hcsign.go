package txscript

import (
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainec"
	"github.com/btcsuite/btcd/wire"
)

// SignatureScript creates an input signature script for tx to spend BTC sent
// from a previous output to the owner of privKey. tx must include all
// transaction inputs and outputs, however txin scripts are allowed to be filled
// or empty. The returned script is calculated to be used as the idx'th txin
// sigscript for tx. subscript is the PkScript of the previous output being used
// as the idx'th input. privKey is serialized in either a compressed or
// uncompressed format based on compress. This format must match the same format
// used to generate the payment address, or the script validation will fail.
func SignatureHCScript(tx *wire.HCMsgTx, idx int, subscript []byte,
	hashType HCSigHashType, privKey chainec.PrivateKey, compress bool) ([]byte,
	error) {
	sig, err := HCRawTxInSignature(tx, idx, subscript, hashType, privKey)

	if err != nil {
		return nil, err
	}

	pubx, puby := privKey.Public()
	pub := chainec.Secp256k1.NewPublicKey(pubx, puby)
	var pkData []byte
	if compress {
		pkData = pub.SerializeCompressed()
	} else {
		pkData = pub.SerializeUncompressed()
	}

	return NewScriptBuilder().AddData(sig).AddData(pkData).Script()
}
func HCRawTxInSignature(tx *wire.HCMsgTx, idx int, subScript []byte,
	hashType HCSigHashType, key chainec.PrivateKey) ([]byte, error) {

	// parsedScript, err := parseScript(subScript)
	// if err != nil {
	// 	return nil, fmt.Errorf("cannot parse output script: %v", err)
	// }
	hash, err := CalcHCSignatureHash(subScript, hashType, tx, idx, nil)
	fmt.Println("len =", len(hex.EncodeToString(hash)), " HCRawTxInSignature = ", hex.EncodeToString(hash))

	if err != nil {
		return nil, err
	}

	r, s, err := chainec.Secp256k1.Sign(key, hash)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}
	sig := chainec.Secp256k1.NewSignature(r, s)

	return append(sig.Serialize(), byte(hashType)), nil
}
