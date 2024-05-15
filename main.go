package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/m-rit/multisigwallet/wallet"
	"github.com/m-rit/multisigwallet/signing"
)

func main() {
	// Create a multisig wallet with 3 shares and threshold 2
	wallet, err := wallet.NewMultiSigWallet(3, 2)
	if err != nil {
		log.Fatal("Error creating wallet:", err)
	}

	// Create a transaction
	tx := wallet.NewTransaction([]string{"input1", "input2"}, []string{"output1", "output2"})
	// Calculate transaction ID
	tx.ID = hex.EncodeToString(tx.Hash())

	// Sign the transaction using two shares
	signature, err := signing.Sign(wallet, 0, 1, tx) // Signing requires providing two share indexes
	if err != nil {
		log.Fatal("Error signing transaction:", err)
	}

	// Print the signature
	fmt.Println("Signature:", signature)
}
