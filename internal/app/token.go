package app

import (
"crypto/tls"
"crypto/x509"
"errors"
"fmt"
"github.com/dgrijalva/jwt-go"
"time"
)

const Issuer = "geo-game"

type JwtAuther interface {
	RequireLogin(scg StandardClaimsGetter, tokenString string) error
}

var _ JwtAuther = (*JwtKey)(nil)

type JwtKey struct {
	keyID     string
	method    jwt.SigningMethod
	signKey   interface{}
	verifyKey interface{}
}

func NewJwtKey(signKey string) *JwtKey {
	return &JwtKey{
		keyID:     "0",
		method:    jwt.SigningMethodHS256,
		signKey:   []byte("test_hmac"),
		verifyKey: []byte("test_hmac"),
	}
}
type StandardClaimsGetter interface {
	jwt.Claims
	GetStandardClaims() *jwt.StandardClaims
}

type AccessToken struct {
	UserID string `json:"userId"`
	jwt.StandardClaims
}


func (at *AccessToken) GetStandardClaims() *jwt.StandardClaims {
	return &at.StandardClaims
}


func (key *JwtKey)GenerateToken(userID string)  (string,error){
	claims:= key.GenerateClaim()
	accessToken := AccessToken{
		UserID:         userID,
		StandardClaims: claims,
	}
	token := jwt.NewWithClaims(key.method, accessToken)

	signedToken,err := token.SignedString(key.signKey)
	// publicKey := loadPublicKey()
	// signedToken,err := token.SignedString(publicKey)
	if err!=nil {
		return "", errors.New("failed to create signedTokenString")
	}
	return signedToken,nil

}

func (key *JwtKey)GenerateClaim()  jwt.StandardClaims{
	claims := jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Second * 900).Unix(),
		Id:        key.keyID,
		IssuedAt:  time.Now().Unix(),
		Issuer:    Issuer,
		NotBefore: time.Now().Unix() - 1,
	}
	return claims
}


func (key *JwtKey) RequireLogin(scg StandardClaimsGetter, tokenString string) error {
	_, err := jwt.ParseWithClaims(tokenString, scg, func(token *jwt.Token) (interface{}, error) {
		if token.Header["alg"] != key.method.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		if scg.GetStandardClaims().Id != key.keyID {
			return nil, fmt.Errorf("the keyId is not known")
		}
		return key.verifyKey, nil
	})
	if err != nil {
		return err
	}
	return validateStandardClaims(scg.GetStandardClaims())
}

func validateStandardClaims(stdClaims *jwt.StandardClaims) error {
	now := time.Now().Unix()
	if !stdClaims.VerifyExpiresAt(now, true) {
		return errors.New("jwt token expired")
	}
	if !stdClaims.VerifyIssuedAt(now, true) {
		return errors.New("jwt token used before issued")
	}
	if !stdClaims.VerifyNotBefore(now, false) {
		return errors.New("jwt token is not valid yet")
	}
	return nil
}

func loadPublicKey() interface{} {
	certPair, err := tls.LoadX509KeyPair("/Users/bhakiyarajkalimuthu/personal/secrets/server.crt", "/Users/bhakiyarajkalimuthu/personal/secrets/server.key")
	if err != nil {
		return nil
	}
	cert, err := x509.ParseCertificate(certPair.Certificate[0])
	if err != nil {
		return nil
	}
	return cert.PublicKey
}

