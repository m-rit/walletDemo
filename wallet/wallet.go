package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
     "vault/shamir"   
)

type MultiSigWallet struct {
	Shares       []string
	RecoveryData *sssa.SecretSet
}

func NewMultiSigWallet(numShares, threshold int) (*MultiSigWallet, error) {
	if numShares < 3 {
		return nil, errors.New("number of shares must be at least 3")
	}
	if threshold < 2 || threshold >= numShares {
		return nil, errors.New("threshold must be between 2 and the number of shares - 1")
	}

	// Generate a private key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Encode private key as hex
	privKeyBytes := append(key.D.Bytes(), key.X.Bytes()...)
	privKeyHex := hex.EncodeToString(privKeyBytes)

	// Split the private key using Shamir's Secret Sharing Scheme
	shares, recoveryData, err := sssa.Create(numShares, threshold, privKeyHex)
	if err != nil {
		return nil, err
	}

	return &MultiSigWallet{
		Shares:       shares,
		RecoveryData: recoveryData,
	}, nil
}

func (wallet *MultiSigWallet) NewTransaction(inputs, outputs []string) *Transaction {
	return &Transaction{
		Inputs:  inputs,
		Outputs: outputs,
	}
}
