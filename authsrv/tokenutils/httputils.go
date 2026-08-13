/**
 * NIST-developed software is provided by NIST as a public service. You may use, copy,
 * and distribute copies of the software in any medium, provided that you keep intact
 * this entire notice. You may improve, modify, and create derivative works of the
 * software or any portion of the software, and you may copy and distribute such modifications
 * or works. Modified works should carry a notice stating that you changed the software and
 * should note the date and nature of any such change. Please explicitly acknowledge the
 * National Institute of Standards and Technology as the source of the software.
 *
 * NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY
 * KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE,
 * NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE
 * OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL
 * BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF
 * THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS,
 * ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.
 *
 * You are solely responsible for determining the appropriateness of using and distributing
 * the software and you assume all risks associated with its use, including but not limited
 * to the risks and costs of program errors, compliance with applicable laws, damage to or
 * loss of data, programs or equipment, and the unavailability or interruption of operation.
 * This software is not intended to be used in any situation where a failure could cause risk
 * of injury or damage to property. The software developed by NIST employees is not subject
 * to copyright protection within the United States
 *
 * This software might use libraries that are under GNU public license or
 * other licenses. Please refer to the licenses of all libraries required
 * by this software.
 *
 *
 * This file contains additional JWT service utilities.
 *
 * Version 0.1
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *
 * 0.1  - 2026/0X/XX - scottr
 *            * Created File.
 */

package tokenutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/dmachard/go-clientsyslog"
)

// internal structure of a client token request
type AuthClientReq struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	ReqScope     string
}

// internal structure for JSON error message
type AuthFailResp struct {
	ErrType string `json:"error"`
	ErrDesc string `json:"error_description"`
	ErrUri  string `json:"error_uri"`
}

/*
 * Connect to syslog server and return Writer
 */
func GenSyslog(logSrv string) *clientsyslog.Writer {
	write, err := clientsyslog.Dial("udp", logSrv, clientsyslog.LOG_ERR, "basicauth")
	if err != nil {
		log.Printf("Unable to reach syslog server: %s", err)
		return nil
	}
	write.SetFramer(clientsyslog.RFC5425MessageLengthFramer)
	write.SetProgram("AuthServer")
	return write
}

// used to generate a new ECDSA key used to sign tokens
func GenerateNewKey() *ecdsa.PrivateKey {

	newPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Printf("Error generating new ECDSA key")
	}
	return newPriv
}

/*
 * This function read in the key file of the Ed25519 key
 * used to generate the JWT returned by the server
 */
func InitKey(mode string, keyfile string) (*ecdsa.PrivateKey, JWKSkey) {
	var encodedPEMdata []byte
	var genPrivKey *ecdsa.PrivateKey

	log.Print("basicauth: setting up private key for auth server")
	if keyfile == "" {
		genPrivKey = GenerateNewKey()
	}

	if mode == "proxy" || mode == "test" {
		encodedPEMdata = []byte(keyfile)
	} else {
		encodedPEMdata = ReadFileAsBytes(keyfile)
		if encodedPEMdata == nil {
			log.Fatalf("Error reading private key file %s", keyfile)
		}
	}
	block, _ := pem.Decode(encodedPEMdata)
	if block == nil {
		log.Fatalf("Failed to decode PEM block")
	}
	genPrivKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("error parsing key, %s", err)
	}
	thePubkey := InitPubKey(genPrivKey)

	return genPrivKey, thePubkey
}

// function to encode X, Y of public key. Trying to avoid Go's
// "depricated" usage of strait BigInts.
func EncodeVal(n *big.Int, size int) string {
	return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, size)))
}

// Genrates the public key in JWK format to return when queried
func InitPubKey(privK *ecdsa.PrivateKey) JWKSkey {

	//get the parameters from the private key
	pubPart := &privK.PublicKey
	theX := EncodeVal(pubPart.X, 32)
	theY := EncodeVal(pubPart.Y, 32)

	retPubKey := JWKSkey{
		KeyType:  "EC",
		KeyCurve: "P-256",
		X:        theX,
		Y:        theY,
		Usage:    "sig",
		Kid:      "basicauth Token Validation Key",
	}

	return retPubKey
}

/* Looks for the auth boundary value in token requests.
 * The request should be in in the form "authboundary::service", but
 * service could be blank (i.e. "authboundary::")
 * the common auth boundaries are some internal and "external" for external
 * communication.
 */
func (req AuthClientReq) GetAudience() (string, error) {
	if req.ReqScope == "" {
		return "", errors.New("Request Scope format incorrect: missing Auth boundary")
	}
	reqScopeParts := strings.Split(req.ReqScope, "::")
	return reqScopeParts[0], nil
}

// Get the client /token request and parse it into
// the proper structure.
func GetClientRequest(r *http.Request) (*AuthClientReq, error) {

	err := r.ParseForm()
	if err != nil {
		log.Printf("Error parsing client request")
	}

	// Access form values
	newClientReq := AuthClientReq{
		//strings.Trim(r.FormValue("grant_type"), "\""),
		r.FormValue("grant_type"),
		r.FormValue("client_id"),
		r.FormValue("client_secret"),
		r.FormValue("scope"),
	}
	if err != nil {
		return &newClientReq, err
	}

	log.Printf("Just got a query from ID: %s", newClientReq.ClientID)
	return &newClientReq, nil
}

/* Depending on the mode, look for the appropriate HTTP header for the
 * SAN of the client sending the query
 * THIS ONLY WORKS WHEN OPERATING IN AN ISTIO SERVICE MESH
 * Need to make more flexible
 */
func GetNameFromHeaders(reqHead http.Header, mode string) (string, error) {
	var myHeader string

	switch mode {
	case "proxy":
		log.Printf("made it to looking for proxy head")
		myHeader = reqHead.Get("X-SME-Forwarded-Client")
	case "mesh":
		myHeader = reqHead.Get("X-Forwarded-Client-Cert")
	}
	if myHeader != "" {
		for substr := range strings.SplitSeq(myHeader, ";") {
			mySan, found := strings.CutPrefix(substr, "URI=")
			if found {
				return mySan, nil
			}
		}
	}
	return "", errors.New("XFCC/XSC Header not present in request")
}

// Get the client cert from HTTP headers
// WORKS WITH ISTIO SERVICE MESH. assumes Envoy sidecar will put the
// default XFCC header.
func GetCertFromHeaders(reqHead http.Header, mode string) (string, error) {
	var myHeader string

	switch mode {
	case "proxy":
		log.Println("Made it to GetCertFromHead using Proxy mode")
		myHeader = reqHead.Get("X-SME-Forwarded-Client")
	case "mesh":
		myHeader = reqHead.Get("X-Forwarded-Client-Cert")
	}
	if myHeader != "" {
		for substr := range strings.SplitSeq(myHeader, ";") {
			mySan, found := strings.CutPrefix(substr, "Hash=")
			if found {
				return mySan, nil
			}
		}
	}
	return "", errors.New("XFCC/XSC Header not present in request")
}
