package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"e_commerce/auth/server/config"
	"encoding/pem"
	"errors"
	"fmt"
)

func NewPrvKey(userId string) (*rsa.PrivateKey, error) {
	prvKey, err := genRsaKey(config.RSAKeyBits)
	if err != nil {
		return nil, err
	}
	err = createPrvKey(userId, encodePrvKey(prvKey))
	if err != nil {
		return nil, fmt.Errorf("failed to save private key to database: %w", err)
	}
	return prvKey, nil
}

func genRsaKey(bits int) (*rsa.PrivateKey, error) {
	prvkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return prvkey, nil
}

func encodePrvKey(prvkey *rsa.PrivateKey) string {
	derStream := x509.MarshalPKCS1PrivateKey(prvkey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	return string(pem.EncodeToMemory(block))
}

func parsePrvKey(prvKeyStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(prvKeyStr))
	if block == nil {
		return nil, fmt.Errorf("No PEM data is found in %s", prvKeyStr)
	}
	prvKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return prvKey, nil
}

func SavePrvKey(userId string, prvKey *rsa.PrivateKey) error {
	if userId == "" {
		return errors.New("user-id and private key should not be empty")
	}
	if err := prvKey.Validate(); err != nil {
		return err
	}
	prvKeyStr := encodePrvKey(prvKey)
	err := updatePrvKey(userId, prvKeyStr)
	if err != nil {
		return fmt.Errorf("failed to update private key: %w", err)
	}
	return nil
}

func LoadPrvKey(userId string) (*rsa.PrivateKey, error) {
	prvKeyStr, err := queryPrvKey(userId)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	prvKey, err := parsePrvKey(prvKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return prvKey, nil
}
