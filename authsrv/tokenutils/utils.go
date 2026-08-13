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
 * This file contains JWT generation/handling utilities.
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
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dmachard/go-clientsyslog"
	"github.com/golang-jwt/jwt/v5"
)

// Used to store the 'cnf' certificate hash
type TokenConfirmation struct {
	CertHash string `json:"x5t#S256"`
}

/* Stuct for JWT claims. Go with default claims and add:
 * type (bearer)
 * roles
 * client cert hash
 */
type BasicClaims struct {
	TokenType    string            `json:"token_type"`
	Roles        string            `json:"roles"`
	Confirmation TokenConfirmation `json:"cnf"`
	jwt.RegisteredClaims
}

// struct used to store the response to a token request (token and metadata)
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpireIn    string `json:"expires_in"`
	Scope       string `json:"scope"`
}

// this type is only used to pre-load Workload entries
type PrivMapping struct {
	WorkloadEntry []WorkPrivs `json:"mappings"`
}

// All of the roles broken down by auth boundary and service name
type WorkPrivs struct {
	WorkloadID string         `json:"workload_id"`
	Privs      []AuthBoundary `json:"privileges"`
}

// Entry for authorization boundary (interna/external)
type AuthBoundary struct {
	Name     string         `json:"audience"`
	Services []ServiceEntry `json:"services"`
}

// Basic unit in mappings. Maps Service name and roles for that service
type ServiceEntry struct {
	Name  string `json:"srvName"`
	Roles string `json:"roles"`
}

// struct used to store and send the JWK when requested
type JWKSkey struct {
	KeyType  string `json:"kty"`
	KeyCurve string `json:"crv"`
	X        string `json:"x"`
	Y        string `json:"y"`
	Usage    string `json:"use"`
	Kid      string `json:"kid"`
}

// Connect to the syslog server if one is configured
func GetSyslogWriter(syslogSrv string) *clientsyslog.Writer {
	w, err := clientsyslog.Dial("tcp", syslogSrv, clientsyslog.LOG_ERR, "auth-server")
	if err != nil {
		log.Printf("Failed to connect to syslog server: %s", err)
	}
	log.Printf("Set up using syslog server at: %s", syslogSrv)
	w.SetFramer(clientsyslog.RFC5425MessageLengthFramer)
	w.SetProgram("basicauth")
	return w
}

func ReadFileAsBytes(filename string) []byte {

	contents, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Cannot open file %s, File not found or has error", filename)
		log.Printf("File read error: %s", err)
	}
	return contents
}

// Compares the requested privileges (from client) to the allowed roles and returns what
// roles should be in the token reply
func GetGrantedScope(reqScope string, allowedScope string) string {
	var finalGrant string

	privs := strings.Split(reqScope, ";")
	for _, aPriv := range privs {
		if strings.Contains(allowedScope, aPriv) {
			if finalGrant != "" {
				finalGrant += ";" + aPriv
			} else {
				finalGrant += aPriv
			}
		}
	}
	return finalGrant
}

// check to see if the given priviledges for a workloadID allows them to
// contact external services
func (wp *WorkPrivs) HasExternal() bool {

	for _, pr := range wp.Privs {
		if pr.Name == "external" {
			return true
		}
	}
	return false
}

// concatinate all the roles for a given workloadID into one string
func (wp *WorkPrivs) AllRoles() string {
	var allroles string

	for _, pr := range wp.Privs {
		if pr.Name != "external" {
			for _, srv := range pr.Services {
				allroles = allroles + " " + srv.Roles
			}
		}
	}

	return strings.TrimSpace(allroles)
}

// Generate the Oauth2 token with the appropriate roles and metadata
func MakeToken(theReq *AuthClientReq, issuer string, workp WorkPrivs, clientHash string, expiry int, idNum string) (*jwt.Token, error) {
	var tokAud string
	var tokroles string
	var peerConfirm TokenConfirmation

	if theReq.ClientID == "" {
		return nil, errors.New("Invalid WorkloadID")
	} else if theReq.GrantType != "client_credentials" {
		return nil, errors.New("Invalid grant_type. Must be 'client_credentials'")
	}
	if workp.WorkloadID == "" {
		return nil, errors.New("Workload not found.")
	}
	tokAud, err := theReq.GetAudience()
	if err != nil {
		log.Printf("Error parsing request Scope: %s", err)
		return nil, errors.New("Invalid scope field in request")
	}

	if tokAud == "external" {
		if workp.HasExternal() {
			tokroles = "external"
			peerConfirm = TokenConfirmation{
				CertHash: "null",
			}
		} else {
			return nil, errors.New("Forbidden Authorization Boundary")
		}
	} else {
		//reduce the scope to what was requested
		// *FOR NOW*: use the full scope, narrow it down in the future
		peerConfirm = TokenConfirmation{
			CertHash: clientHash,
		}
		tokroles = workp.AllRoles()
	}

	curTime := time.Now()

	expireTime := curTime.Add(time.Duration(expiry) * time.Second)
	claims := BasicClaims{
		"Bearer",
		tokroles,
		peerConfirm,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expireTime),
			IssuedAt:  jwt.NewNumericDate(curTime),
			NotBefore: jwt.NewNumericDate(curTime),
			Issuer:    issuer,
			Subject:   theReq.ClientID,
			ID:        idNum, //FIX THIS
			Audience:  []string{tokAud},
		},
	}

	theToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	return theToken, nil
}

// Generates the JWT data object to be signed by the appropriate key
func GenJWT(myTok *jwt.Token, exp string, pubScope string, sigKey *ecdsa.PrivateKey) ([]byte, error) {

	signedTok, err := myTok.SignedString(sigKey)
	TokeResp := TokenResponse{
		AccessToken: signedTok,
		TokenType:   "Bearer",
		ExpireIn:    exp,
		Scope:       pubScope,
	}
	if err != nil {
		return nil, err
	}
	retValue, err := json.Marshal(TokeResp)
	if err != nil {
		return nil, err
	}
	return retValue, nil
}

// takes the intial mapping file (intial configuration) and creates the internal role
// structures.
func LoadScopeMapping(scopeFilename string) map[string]WorkPrivs {
	var myAuthScopes PrivMapping
	myMapping := make(map[string]WorkPrivs)

	//Open the file
	jsonMapping := ReadFileAsBytes(scopeFilename)
	if jsonMapping == nil {
		log.Print("No Initial Mapping Found, going with empty scope mapping.")
	} else {
		//Now marshal into the data struct and make the map
		json.Unmarshal(jsonMapping, &myAuthScopes)
		for i := 0; i < len(myAuthScopes.WorkloadEntry); i++ {
			myMapping[myAuthScopes.WorkloadEntry[i].WorkloadID] = myAuthScopes.WorkloadEntry[i]
		}
	}
	return myMapping
}

// collect the current mapping database and return it. Called from the /control API to see
// current state of workloadID:role mappings
func GetAllMappings(scopeMap map[string]WorkPrivs) PrivMapping {
	var curAuthMap PrivMapping

	for _, ent := range scopeMap {
		curAuthMap.WorkloadEntry = append(curAuthMap.WorkloadEntry, ent)
	}
	return curAuthMap
}

// Generate the JSON error message to return when service error is to be returned
// NOTE: not called for all 404 responses, Gorilla MUX takes care of that
func GenErrResponse(badReq *AuthClientReq, errString string, code int) *AuthFailResp {
	var resp AuthFailResp

	if badReq.GrantType != "client_credentials" {
		log.Print("Error response is unsupported grant type")
		//Bad Grant Type
		resp.ErrType = "unsupported_grant_type"
		resp.ErrDesc = "Grant type not supported - must be 'client_credentials'"
	}
	if badReq.ClientID == "" {
		//Unknown client ID
		log.Print("Error response is invalid client")
		resp.ErrType = "invalid_client"
		resp.ErrDesc = errString
	}
	if code == 404 {
		log.Print("Error response is unknown client")
		resp.ErrType = "unknown_client"
		resp.ErrDesc = errString
	}

	return &resp
}

// helper function to generate a SHA256 hash from the cert seen in HTTP headers
func GenHashFromCert(cert []byte) string {
	hash := sha256.Sum256(cert)
	hashAsSlice := hash[:]
	encode := base64.StdEncoding.EncodeToString(hashAsSlice)

	return encode
}
