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
 * This file contains some unit tests for the httputils.go file functions.
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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestGetAudience(t *testing.T) {
	var testReq = AuthClientReq{
		"bearer",
		"clientT",
		"null",
		"internal::foo",
	}

	result, err := testReq.GetAudience()
	if result != "internal" && err == nil {
		t.Errorf("Error: GetAudience failed to parse Req Scope")
	}
	testReq.ReqScope = ""
	result, err = testReq.GetAudience()
	if err == nil {
		t.Errorf("Error: Get Audience failed when scope is blank")
	}
}

func TestGetNameFromHeaders(t *testing.T) {
	var testHeader *http.Request
	var badHeader *http.Request
	var result string

	testHeader, err := http.NewRequest(http.MethodGet, "http://example.com/", strings.NewReader("request body"))
	if err != nil {
		t.Errorf("GetNameFromHeaders ERROR - can't make test request")
	}
	testHeader.Header.Add("X-Forwarded-Client-Cert", "By=spiffe://testbed.local/service;Hash=foobar;extrabit;URI=spiffe://testbed.local/service")
	result, err = GetNameFromHeaders(testHeader.Header, "mesh")
	if result != "spiffe://testbed.local/service" {
		t.Errorf("Error extracting cert string from header, got: %s", result)
	}
	testHeader.Header.Set("X-Forwarded-Client-Cert", "By=spiffe://testbed.local/service;Hash=foobar;extrabit;URI=")
	result, err = GetNameFromHeaders(testHeader.Header, "mesh")
	if result != "" {
		t.Errorf("Bad header did not return blank string, got: %s", result)
	}
	badHeader, err = http.NewRequest(http.MethodGet, "http://example.com/", strings.NewReader("request body"))
	if err != nil {
		t.Errorf("GetNameFromHeaders ERROR - can't make test request")
	}
	badHeader.Header.Add("X-Bad-Header", "By=spiffe://testbed.local/service;Hash=foobar;extrabit;URI=spiffe://testbed.local/service")
	result, err = GetNameFromHeaders(badHeader.Header, "mesh")
	if result != "" {
		t.Errorf("Bad header did not return blank string, got: %s", result)
	}
}

func TestGetClientRequest(t *testing.T) {
	data := url.Values{}
	data.Set("grant_type", "bearer")
	data.Set("client_id", "Client1")
	data.Set("client_secret", "secret-string")
	data.Set("scope", "priv1;priv2")

	req, err := http.NewRequest("POST", "http://example.com/", strings.NewReader(data.Encode()))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	clientReqStruct, err := GetClientRequest(req)
	if clientReqStruct.ClientID != "Client1" {
		t.Errorf("failed to extract client request")
	}

}
