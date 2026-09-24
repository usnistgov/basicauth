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
 * This file contains the core Oauth2 server that listens for token requests.
 *
 * Version 0.1
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *
 * 0.1  - 2026/09/25 - scottr
 *            * initial release.
 */

package authsrv

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/dmachard/go-clientsyslog"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"gitlab.nist.gov/scottr/basicauth/authsrv/tokenutils"
)

type ServConfig struct {
	Service struct {
		Mode    string `mapstructure:"mode"`
		Issuer  string `mapstructure:"issuer"`
		PrivKey string `mapstructure:"privkey"`
		ExtKey  string `mapstructure:"extkey"`
		Expiry  string `mapstructure:"expiry"`
	} `mapstructure:"service"`
	Addr       string `mapstructure:"addr"`
	Port       string `mapstructure:"port"`
	PathPrefix string `mapstructure:"prefix"`
	Mapping    string `mapstructure:"mapping"`
	Logging    string `mapstructure:"logging"`
	HttpsKey   string `mapstructure:"httpskey"`
	HttpsCert  string `mapstructure:"httpscert"`
	CaCert     string `mapstructure:"cacert"`
}

var (
	srvConfig    ServConfig
	myPrivKey    *ecdsa.PrivateKey
	myExtKey     *ecdsa.PrivateKey
	myJwksPubkey tokenutils.JWKSkey
	tokScopes    map[string]tokenutils.WorkPrivs
	usingHttps   bool
	tokenIDNum   int
	syslog       bool
	sysLogger    *clientsyslog.Writer
)

// helper utility to convert SPIFFE URL into a string.
func GetSpiffeID(spiffeURI *url.URL) string {
	return spiffeURI.String()
}

// Called when client requests the JWK needed to validate
// token signatures.
func KeyHandler(w http.ResponseWriter, r *http.Request) {
	var client string

	client = r.RemoteAddr
	if syslog {
		sysLogger.Info(client + " has sent request for JWKS.")
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(200)
	err := json.NewEncoder(w).Encode(myJwksPubkey)
	if err != nil {
		log.Printf("Error when generated response for JWK, %s", err)
		if syslog {
			sysLogger.Err("Error when generating JWKS response to " + client)
		}
	}
}

func TokenHandler(w http.ResponseWriter, r *http.Request) {
	var retValue []byte
	var err error
	var reqClient, clientName string
	var clientCertHash string
	var external bool
	var retToken *jwt.Token
	var client string

	external = false
	client = r.RemoteAddr
	newReq, err := tokenutils.GetClientRequest(r)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if usingHttps {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	if syslog {
		sysLogger.Info("Token request from: " + client)
	}
	//first, checks on the request, then generate the token if checks pass
	log.Printf("Going to generate a response for %s", newReq.ClientID)
	reqClient = newReq.ClientID
	switch srvConfig.Service.Mode {
	case "standalone":
		clientCert := r.TLS.PeerCertificates[0].Raw
		clientCertHash = tokenutils.GenHashFromCert(clientCert)
		clientName = GetSpiffeID(r.TLS.PeerCertificates[0].URIs[0])
	case "mesh":
		clientName, err = tokenutils.GetNameFromHeaders(r.Header, "mesh")
		if err != nil {
			clientName = ""
		}
		clientCertHash, err = tokenutils.GetCertFromHeaders(r.Header, "mesh")
		if err != nil {
			clientCertHash = "nil"
		}
	case "test":
		clientName = reqClient
		clientCertHash = "111111111111111111111111111111111"
	case "proxy":
		//In proxy/SME mode, we only use the name in the certificate.
		clientName, err = tokenutils.GetNameFromHeaders(r.Header, "proxy")
		if err != nil {
			clientName = ""
		}
		clientCertHash, err = tokenutils.GetCertFromHeaders(r.Header, "proxy")
		if err != nil {
			clientCertHash = "nil"
		}
		//ignore reqClient, since we only go off of the SAN in the mTLS client cert
		//This is not to the draft, but a special case for O-RAN prototype
		reqClient = clientName
	}

	if clientName != reqClient {
		clientName = ""
	}
	log.Printf("Made it to before MakeToken with clientName: %s", clientName)
	if syslog {
		sysLogger.Info("Generating token for: [" + newReq.ClientID + "] request from: " + client)
	}
	ttl, err := strconv.Atoi(srvConfig.Service.Expiry)
	retToken, err = tokenutils.MakeToken(newReq, srvConfig.Service.Issuer, tokScopes[clientName], clientCertHash, ttl, strconv.Itoa(tokenIDNum))

	if err == nil {
		tokenIDNum++
		if external {
			retValue, err = tokenutils.GenJWT(retToken, srvConfig.Service.Expiry, newReq.ReqScope, myExtKey)
		} else {
			retValue, err = tokenutils.GenJWT(retToken, srvConfig.Service.Expiry, newReq.ReqScope, myPrivKey)
		}
		if err != nil {
			log.Printf("Error Generating Token Response, %s", err)
			if syslog {
				sysLogger.Err("Error generating/signing token for: " + client)
			}
		}
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(200)
	} else {
		var code int
		w.Header().Set("content-type", "application/problem+json")
		if err.Error() == "Invalid WorkloadID" || err.Error() == "Workload not found." {
			w.WriteHeader(404)
			code = 404
		} else {
			w.WriteHeader(400)
			code = 400
		}
		errResp := tokenutils.GenErrResponse(newReq, err.Error(), code)
		errResp.ErrUri = "/oauth2/v1/token"
		retValue, err = json.Marshal(errResp)
		if err != nil {
			log.Printf("Error creating JSON error response, %s", err)
		}
		if syslog {
			sysLogger.Err("Error returned from failed token request: " + err.Error() + " client: " + client)
		}
	}
	w.Write(retValue)
}

// Called to add a new set of workloadID:roles mapping to the internal data store
func ProvisionHandler(w http.ResponseWriter, r *http.Request) {
	var newEntry tokenutils.WorkPrivs
	var client string

	client = r.RemoteAddr
	log.Printf("Received new entry request")
	if syslog {
		sysLogger.Info("Request to add new WorkloadID mapping from: " + client)
	}
	err := json.NewDecoder(r.Body).Decode(&newEntry)
	if err != nil {
		log.Printf("Error parsing new API registration")
		if syslog {
			errStr := "Error adding new mapping for workloadID " + newEntry.WorkloadID + " by request from: " + client
			sysLogger.Info(errStr)
		}
		w.WriteHeader(400)
	}
	//add it to the mapping
	tokScopes[newEntry.WorkloadID] = newEntry

	if usingHttps {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	w.WriteHeader(201)
	//right now, this is "all" need to change to scope mapping
	log.Printf("Sending - has an empty body in response")
	if syslog {
		logStr := "New mapping for workloadID " + newEntry.WorkloadID + " added by request from: " + client
		sysLogger.Info(logStr)
	}

	w.Write(nil)
}

// Called to get a copy of the current internal data store of WorkloadID:roles mappings
func GetProvisionHandler(w http.ResponseWriter, r *http.Request) {
	var client string

	client = r.RemoteAddr
	if usingHttps {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	}
	//right now, this is "all" need to change to scope mapping
	log.Printf("Call for mappings. Going to generate a response")
	if syslog {
		sysLogger.Info("Call for auth server role mappings from: " + client)
	}

	allMapping := tokenutils.GetAllMappings(tokScopes)
	retValue, err := json.Marshal(allMapping)
	if err != nil {
		log.Printf("Error creating JSON token response, %s", err)
	}
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(200)
	w.Write(retValue)
}

// Handles calls to the /control endpoint.  Currently, only 'shutdown' and
// 'new' is availble. This is meant to be an out-of-band means to manage the
// basicauth service when running demos/experiments, etc.
func CommandHandler(w http.ResponseWriter, r *http.Request) {
	var shutdown bool
	shutdown = false

	//get parameters. Right now we don't do anything with them
	queryP := r.URL.Query()

	//will have switch here on what to do based on signal param
	for key, values := range queryP {
		switch key {
		case "shutdown":
			shutdown = true
			if values[0] == "good" {
				log.Println("Got Command to Shutdown - shutting down")
			} else {
				log.Println("Comamnd to kill server process")
			}
		case "new":
			ProvisionHandler(w, r)
		case "provision":
			GetProvisionHandler(w, r)
		}
	}
	//send back success, then shutdown
	w.WriteHeader(204)
	w.Write(nil)
	if shutdown {
		os.Exit(0)
	}
}

// Function called by main() that starts everything.
func Execute() {
	var cfg *tls.Config
	var srv *http.Server

	//use viper to read in configuration file
	viper.SetConfigType("yaml")
	viper.AddConfigPath("./")
	viper.AddConfigPath("/conf")
	viper.SetConfigFile("basicauth-config.yaml")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading configuration file: %s", err)
	}
	err = viper.Unmarshal(&srvConfig)
	if err != nil {
		log.Fatalf("error processing config file, %s", err)
	}

	/* Do inialization tasks
	 * Keys for signing JWTs
	 * Read in pre-configured role mappings
	 * Initialize connection to syslog server (if configured)
	 */
	myPrivKey, myJwksPubkey = tokenutils.InitKey(srvConfig.Service.Mode, srvConfig.Service.PrivKey)
	tokScopes = tokenutils.LoadScopeMapping(srvConfig.Mapping)
	tokenIDNum = 0 //initalize token ID
	syslog = false
	if srvConfig.Logging != "" {
		sysLogger = tokenutils.GenSyslog(srvConfig.Logging)
		syslog = true
	}
	log.Print("Auth server finished reading in config files")

	//If operating in standalone mode, configure the TLS configuration
	if srvConfig.Service.Mode == "standalone" && srvConfig.HttpsKey != "" {
		//Standalone mode, use TLS
		usingHttps = true
		localCa, err := os.ReadFile(srvConfig.CaCert)
		if err != nil {
			log.Fatalf("Can't load local root cert, exiting: %s", err)
		}
		caPool := x509.NewCertPool()
		caPool.AppendCertsFromPEM(localCa)
		cfg = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			InsecureSkipVerify:       true, //REMOVE ONCE THINGS GET WORKING!!!!
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			ClientAuth:               tls.RequireAnyClientCert,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
		}
	}

	// Setting up the routes by creating a new Gorilla MUX router
	router := mux.NewRouter()
	router.HandleFunc(srvConfig.PathPrefix+"/token", TokenHandler).Methods("POST")
	router.HandleFunc(srvConfig.PathPrefix+"/jwks", KeyHandler).Methods("GET")
	router.HandleFunc("/control", CommandHandler).Methods("POST")
	router.HandleFunc("/control/provision", GetProvisionHandler).Methods("GET")
	router.HandleFunc("/control/provision/new", ProvisionHandler).Methods("POST")
	log.Print("basicAuth - set up routes")

	myListenAddress := srvConfig.Addr + ":" + srvConfig.Port
	if syslog {
		sysLogger.Info("basicAuth starting on " + myListenAddress)
	}
	if usingHttps {
		//Create a HTTPS server with the right context and keypair
		srv = &http.Server{
			Handler:      router,
			Addr:         myListenAddress,
			TLSConfig:    cfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
			// enforce timeouts
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}
		log.Fatal(srv.ListenAndServeTLS(srvConfig.HttpsCert, srvConfig.HttpsKey))
	} else {
		//Create a plain HTTP server. This assumes basicauth is running in a service mesh or
		// some other proxy is terminating mTLS for us
		srv = &http.Server{
			Handler: router,
			Addr:    myListenAddress,
			// enforce timeouts
			WriteTimeout: 15 * time.Second,
			ReadTimeout:  15 * time.Second,
		}
		log.Printf("starting http service in mode: %s", srvConfig.Service.Mode)
		log.Fatal(srv.ListenAndServe())
	}
}
