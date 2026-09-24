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
 * This file contains unit tests for select functions in utils.go.
 *
 * Version 0.1
 *
 * ChangeLog:
 * -----------------------------------------------------------------------------
 *
 * 0.1  - 2026/09/25 - scottr
 *            * Initial Public Release.
 */
package tokenutils

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

var (
	serviceA = ServiceEntry{
		"serviceA",
		"role1 role2",
	}
	serviceAEx = ServiceEntry{
		"serviceEx",
		"external",
	}
	serviceB = ServiceEntry{
		"serviceB",
		"role1 role3",
	}
	serviceC = ServiceEntry{
		"serviceC",
		"role4 role5",
	}

	authBoundExt = AuthBoundary{
		"external",
		[]ServiceEntry{serviceAEx},
	}
	authBoundA = AuthBoundary{
		"internal",
		[]ServiceEntry{serviceA},
	}

	authBoundIntonly = AuthBoundary{
		"intOnly",
		[]ServiceEntry{serviceB, serviceC},
	}

	workloadA = WorkPrivs{
		"workloadIDA",
		[]AuthBoundary{authBoundA, authBoundExt},
	}
	workloadB = WorkPrivs{
		"workloadIDB",
		[]AuthBoundary{authBoundIntonly},
	}
)

func TestGenErrResponse(t *testing.T) {
	var resp AuthFailResp
	var failReq AuthClientReq

	failReq.ClientID = ""
	failReq.GrantType = "client_credentials"
	resp = *GenErrResponse(&failReq, "nothing", 400)
	if resp.ErrType != "invalid_client" {
		t.Errorf("Incorrect Type in Error Response to %s", "nil ClientID")
	}
	failReq.ClientID = "foobar"
	failReq.GrantType = "foobar"
	resp = *GenErrResponse(&failReq, "Foobar", 400)
	if resp.ErrType != "unsupported_grant_type" {
		t.Errorf("Incorrect Type in Error Response to %s", "Grant is foobar")
	}
}

func TestMakeToken(t *testing.T) {
	var testReq AuthClientReq
	var returnedToken *jwt.Token

	testReq.ClientID = ""
	testReq.GrantType = "client_credentials"
	returnedToken, err := MakeToken(&testReq, "tester", workloadA, "hashstring", 30, "1")
	if returnedToken != nil && err != nil {
		t.Errorf("Bad Token generated when ClientID is nil")
	}
	testReq.ClientID = "foobar"
	testReq.GrantType = "foobar"
	returnedToken, err = MakeToken(&testReq, "tester", workloadA, "hashstring", 30, "1")
	if returnedToken != nil && err != nil {
		t.Errorf("Bad Token generated when GrantType is incorrect")
	}
	testReq.ClientID = workloadA.WorkloadID
	returnedToken, err = MakeToken(&testReq, "tester", workloadA, "hashstring", 30, "1")
	if returnedToken == nil && err == nil {
		t.Errorf("Failed to generate token")
	}

}

func TestGetGrantedScope(t *testing.T) {
	var registeredScopes string
	var requestedScope string
	var retScope string

	registeredScopes = "priv1;priv2;priv3"
	requestedScope = "priv1"
	retScope = GetGrantedScope(requestedScope, registeredScopes)
	if retScope != "priv1" {
		t.Error("Error granting 1 priv out of 1 requested")
	}
	requestedScope = "priv1;priv3"
	retScope = GetGrantedScope(requestedScope, registeredScopes)
	if retScope != "priv1;priv3" {
		t.Error("Error granting privs out of 2 requested")
	}
	requestedScope = "priv4"
	retScope = GetGrantedScope(requestedScope, registeredScopes)
	if retScope != "" {
		t.Error("Error granting 0 priv when requesting extra privs")
	}
	requestedScope = "priv1;priv4"
	retScope = GetGrantedScope(requestedScope, registeredScopes)
	if retScope != "priv1" {
		t.Error("Error granting 1 priv when requesting 1 valid and 1 invalid")
	}
}

func TestHasExternal(t *testing.T) {

	//has external, should return True
	result := workloadA.HasExternal()
	if !result {
		t.Error("Error - workloadA has external privs, but failed check")
	}
	result = workloadB.HasExternal()
	if result {
		t.Error("Error - workloadB does not have external privs, but failed check")
	}
}

func TestAllRoles(t *testing.T) {

	result := workloadA.AllRoles()
	if result != "role1 role2" {
		t.Error("Error - workloadA has incorrect list of AllRoles")
	}
	result = workloadB.AllRoles()
	if result != "role1 role3 role4 role5" {
		t.Error("Error - workloadB has incorrect list of AllRoles: " + result)
	}
}

func TestGetAllMappings(t *testing.T) {
	testScopeMap := make(map[string]WorkPrivs)
	testScopeMap[workloadA.WorkloadID] = workloadA
	testScopeMap[workloadB.WorkloadID] = workloadB

	result := GetAllMappings(testScopeMap)
	if (result.WorkloadEntry[0].WorkloadID != workloadA.WorkloadID) && (result.WorkloadEntry[0].WorkloadID != workloadB.WorkloadID) {
		t.Error("Error - GetAllMappings: Incorrect array of WorkPrivs: " + result.WorkloadEntry[0].WorkloadID)
	}
	if (result.WorkloadEntry[1].WorkloadID != workloadA.WorkloadID) && (result.WorkloadEntry[1].WorkloadID != workloadB.WorkloadID) {
		t.Error("Error - GetAllMappings: Incorrect array of WorkPrivs")
	}
	if result.WorkloadEntry[0].WorkloadID == result.WorkloadEntry[1].WorkloadID {
		t.Error("Error - GenAllMappings: Same WorkPrivs repeated.")
	}
}

func TestGenHashFromCert(t *testing.T) {
	testStr := "AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPPQQRRSSTTUUVVWWXXYYZZ"
	testStrAsBytes := []byte(testStr)
	compare := "c6mNwTKlcGuCRSPeWW6lo8dC29ljgaTr4iUMq/98L6Y="
	result := GenHashFromCert(testStrAsBytes)
	if result != compare {
		t.Error("Error - GenHashFromCert hash incorrect: ")
	}
}
