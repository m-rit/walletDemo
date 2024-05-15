package signing

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"math/big"

	"github.com/m-rit/multisigwallet/wallet"
	"github.com/codahale/snefru"
)

type Transaction = wallet.Transaction

func Sign(wallet *wallet.MultiSigWallet, shareIndex1, shareIndex2 int, tx *Transaction) (string, error) {
	if shareIndex1 < 0 || shareIndex1 >= len(wallet.Shares) || shareIndex2 < 0 || shareIndex2 >= len(wallet.Shares) {
		return "", errors.New("invalid share index")
	}

	// Reconstruct the private key using the shares
	privKeyHex, err := sssa.Combine(wallet.RecoveryData, []string{wallet.Shares[shareIndex1], wallet.Shares[shareIndex2]})
	if err != nil {
		return "", err
	}

	// Decode private key from hex
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", err
	}

	// Extract D and X components from private key bytes
	dBytes := privKeyBytes[:32]
	xBytes := privKeyBytes[32:]

	// Create ecdsa.PrivateKey
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(xBytes),
		},
		D: new(big.Int).SetBytes(dBytes),
	}

	// Sign the transaction
	r, s, err := ecdsa.Sign(rand.Reader, privKey, tx.Hash())
	if err != nil {
		return "", err
	}

	// Encode signature as hex
	return hex.EncodeToString(r.Bytes()) + hex.EncodeToString(s.Bytes()), nil
}

func (tx *Transaction) Hash() []byte {
	data := ""
	for _, input := range tx.Inputs {
		data += input
	}
	for _, output := range tx.Outputs {
		data += output
	}
	return snefru.Sum256([]byte(data))
}
