/*
 *
 * Copyright 2016 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package credentials

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/internal/grpctest"
	"google.golang.org/grpc/testdata"
)

const defaultTestTimeout = 10 * time.Second

type s struct {
	grpctest.Tester
}

func Test(t *testing.T) {
	grpctest.RunSubTests(t, s{})
}

// A struct that implements AuthInfo interface but does not implement GetCommonAuthInfo() method.
type testAuthInfoNoGetCommonAuthInfoMethod struct{}

func (ta testAuthInfoNoGetCommonAuthInfoMethod) AuthType() string {
	return "testAuthInfoNoGetCommonAuthInfoMethod"
}

// A struct that implements AuthInfo interface and implements CommonAuthInfo() method.
type testAuthInfo struct {
	CommonAuthInfo
}

func (ta testAuthInfo) AuthType() string {
	return "testAuthInfo"
}

func (s) TestCheckSecurityLevel(t *testing.T) {
	testCases := []struct {
		authLevel SecurityLevel
		testLevel SecurityLevel
		want      bool
	}{
		{
			authLevel: PrivacyAndIntegrity,
			testLevel: PrivacyAndIntegrity,
			want:      true,
		},
		{
			authLevel: IntegrityOnly,
			testLevel: PrivacyAndIntegrity,
			want:      false,
		},
		{
			authLevel: IntegrityOnly,
			testLevel: NoSecurity,
			want:      true,
		},
		{
			authLevel: InvalidSecurityLevel,
			testLevel: IntegrityOnly,
			want:      true,
		},
		{
			authLevel: InvalidSecurityLevel,
			testLevel: PrivacyAndIntegrity,
			want:      true,
		},
	}
	for _, tc := range testCases {
		err := CheckSecurityLevel(testAuthInfo{CommonAuthInfo: CommonAuthInfo{SecurityLevel: tc.authLevel}}, tc.testLevel)
		if tc.want && (err != nil) {
			t.Fatalf("CheckSeurityLevel(%s, %s) returned failure but want success", tc.authLevel.String(), tc.testLevel.String())
		} else if !tc.want && (err == nil) {
			t.Fatalf("CheckSeurityLevel(%s, %s) returned success but want failure", tc.authLevel.String(), tc.testLevel.String())

		}
	}
}

func (s) TestCheckSecurityLevelNoGetCommonAuthInfoMethod(t *testing.T) {
	if err := CheckSecurityLevel(testAuthInfoNoGetCommonAuthInfoMethod{}, PrivacyAndIntegrity); err != nil {
		t.Fatalf("CheckSeurityLevel() returned failure but want success")
	}
}

func (s) TestTLSOverrideServerName(t *testing.T) {
	expectedServerName := "server.name"
	c := NewTLS(nil)
	c.OverrideServerName(expectedServerName)
	if c.Info().ServerName != expectedServerName {
		t.Fatalf("c.Info().ServerName = %v, want %v", c.Info().ServerName, expectedServerName)
	}
}

func (s) TestTLSClone(t *testing.T) {
	expectedServerName := "server.name"
	c := NewTLS(nil)
	c.OverrideServerName(expectedServerName)
	cc := c.Clone()
	if cc.Info().ServerName != expectedServerName {
		t.Fatalf("cc.Info().ServerName = %v, want %v", cc.Info().ServerName, expectedServerName)
	}
	cc.OverrideServerName("")
	if c.Info().ServerName != expectedServerName {
		t.Fatalf("Change in clone should not affect the original, c.Info().ServerName = %v, want %v", c.Info().ServerName, expectedServerName)
	}

}

type serverHandshake func(net.Conn) (AuthInfo, error)

func (s) TestClientHandshakeReturnsAuthInfo(t *testing.T) {
	tcs := []struct {
		name    string
		address string
	}{
		{
			name:    "localhost",
			address: "localhost:0",
		},
		{
			name:    "ipv4",
			address: "127.0.0.1:0",
		},
		{
			name:    "ipv6",
			address: "[::1]:0",
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan AuthInfo, 1)
			lis := launchServerOnListenAddress(t, tlsServerHandshake, done, tc.address)
			defer lis.Close()
			lisAddr := lis.Addr().String()
			clientAuthInfo := clientHandle(t, gRPCClientHandshake, lisAddr)
			// wait until server sends serverAuthInfo or fails.
			serverAuthInfo, ok := <-done
			if !ok {
				t.Fatalf("Error at server-side")
			}
			if !compare(clientAuthInfo, serverAuthInfo) {
				t.Fatalf("c.ClientHandshake(_, %v, _) = %v, want %v.", lisAddr, clientAuthInfo, serverAuthInfo)
			}
		})
	}
}

func (s) TestServerHandshakeReturnsAuthInfo(t *testing.T) {
	done := make(chan AuthInfo, 1)
	lis := launchServer(t, gRPCServerHandshake, done)
	defer lis.Close()
	clientAuthInfo := clientHandle(t, tlsClientHandshake, lis.Addr().String())
	// wait until server sends serverAuthInfo or fails.
	serverAuthInfo, ok := <-done
	if !ok {
		t.Fatalf("Error at server-side")
	}
	if !compare(clientAuthInfo, serverAuthInfo) {
		t.Fatalf("ServerHandshake(_) = %v, want %v.", serverAuthInfo, clientAuthInfo)
	}
}

func (s) TestServerAndClientHandshake(t *testing.T) {
	done := make(chan AuthInfo, 1)
	lis := launchServer(t, gRPCServerHandshake, done)
	defer lis.Close()
	clientAuthInfo := clientHandle(t, gRPCClientHandshake, lis.Addr().String())
	// wait until server sends serverAuthInfo or fails.
	serverAuthInfo, ok := <-done
	if !ok {
		t.Fatalf("Error at server-side")
	}
	if !compare(clientAuthInfo, serverAuthInfo) {
		t.Fatalf("AuthInfo returned by server: %v and client: %v aren't same", serverAuthInfo, clientAuthInfo)
	}
}

func compare(a1, a2 AuthInfo) bool {
	if a1.AuthType() != a2.AuthType() {
		return false
	}
	switch a1.AuthType() {
	case "tls":
		state1 := a1.(TLSInfo).State
		state2 := a2.(TLSInfo).State
		if state1.Version == state2.Version &&
			state1.HandshakeComplete == state2.HandshakeComplete &&
			state1.CipherSuite == state2.CipherSuite &&
			state1.NegotiatedProtocol == state2.NegotiatedProtocol {
			return true
		}
		return false
	default:
		return false
	}
}

func launchServer(t *testing.T, hs serverHandshake, done chan AuthInfo) net.Listener {
	return launchServerOnListenAddress(t, hs, done, "localhost:0")
}

func launchServerOnListenAddress(t *testing.T, hs serverHandshake, done chan AuthInfo, address string) net.Listener {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		if strings.Contains(err.Error(), "bind: cannot assign requested address") ||
			strings.Contains(err.Error(), "socket: address family not supported by protocol") {
			t.Skipf("no support for address %v", address)
		}
		t.Fatalf("Failed to listen: %v", err)
	}
	go serverHandle(t, hs, done, lis)
	return lis
}

// Is run in a separate goroutine.
func serverHandle(t *testing.T, hs serverHandshake, done chan AuthInfo, lis net.Listener) {
	serverRawConn, err := lis.Accept()
	if err != nil {
		t.Errorf("Server failed to accept connection: %v", err)
		close(done)
		return
	}
	serverAuthInfo, err := hs(serverRawConn)
	if err != nil {
		t.Errorf("Server failed while handshake. Error: %v", err)
		serverRawConn.Close()
		close(done)
		return
	}
	done <- serverAuthInfo
}

func clientHandle(t *testing.T, hs func(net.Conn, string) (AuthInfo, error), lisAddr string) AuthInfo {
	conn, err := net.Dial("tcp", lisAddr)
	if err != nil {
		t.Fatalf("Client failed to connect to %s. Error: %v", lisAddr, err)
	}
	defer conn.Close()
	clientAuthInfo, err := hs(conn, lisAddr)
	if err != nil {
		t.Fatalf("Error on client while handshake. Error: %v", err)
	}
	return clientAuthInfo
}

// Server handshake implementation in gRPC.
func gRPCServerHandshake(conn net.Conn) (AuthInfo, error) {
	serverTLS, err := NewServerTLSFromFile(testdata.Path("x509/server1_cert.pem"), testdata.Path("x509/server1_key.pem"))
	if err != nil {
		return nil, err
	}
	_, serverAuthInfo, err := serverTLS.ServerHandshake(conn)
	if err != nil {
		return nil, err
	}
	return serverAuthInfo, nil
}

// Client handshake implementation in gRPC.
func gRPCClientHandshake(conn net.Conn, lisAddr string) (AuthInfo, error) {
	clientTLS := NewTLS(&tls.Config{InsecureSkipVerify: true})
	ctx, cancel := context.WithTimeout(context.Background(), defaultTestTimeout)
	defer cancel()
	_, authInfo, err := clientTLS.ClientHandshake(ctx, lisAddr, conn)
	if err != nil {
		return nil, err
	}
	return authInfo, nil
}

func tlsServerHandshake(conn net.Conn) (AuthInfo, error) {
	cert, err := tls.LoadX509KeyPair(testdata.Path("x509/server1_cert.pem"), testdata.Path("x509/server1_key.pem"))
	if err != nil {
		return nil, err
	}
	serverTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
	}
	serverConn := tls.Server(conn, serverTLSConfig)
	err = serverConn.Handshake()
	if err != nil {
		return nil, err
	}
	return TLSInfo{State: serverConn.ConnectionState(), CommonAuthInfo: CommonAuthInfo{SecurityLevel: PrivacyAndIntegrity}}, nil
}

func tlsClientHandshake(conn net.Conn, _ string) (AuthInfo, error) {
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true, // NOLINT
		NextProtos:         []string{"h2"},
	}
	clientConn := tls.Client(conn, clientTLSConfig)
	if err := clientConn.Handshake(); err != nil {
		return nil, err
	}
	return TLSInfo{State: clientConn.ConnectionState(), CommonAuthInfo: CommonAuthInfo{SecurityLevel: PrivacyAndIntegrity}}, nil
}

// testWaitForStreamFunctionalReady implements WaitForStreamFunctionalReady for testing
type testWaitForStreamFunctionalReady struct {
	token                       string
	waitForFunctionalReady      bool
	validateShouldPass          bool
	getMetadataCalled           bool
	validateFunctionalReadyCalled bool
	waitForFunctionalReadyCalled  bool
	requireTransportSec         bool
}

func (c *testWaitForStreamFunctionalReady) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	c.getMetadataCalled = true
	return map[string]string{"authorization": "Bearer " + c.token}, nil
}

func (c *testWaitForStreamFunctionalReady) RequireTransportSecurity() bool {
	return c.requireTransportSec
}

func (c *testWaitForStreamFunctionalReady) WaitForStreamFunctionalReady() bool {
	c.waitForFunctionalReadyCalled = true
	return c.waitForFunctionalReady
}

func (c *testWaitForStreamFunctionalReady) ValidateStreamFunctionalReady(responseHeaders map[string][]string) error {
	c.validateFunctionalReadyCalled = true
	if !c.validateShouldPass {
		return errors.New("stream functional ready validation failed: server not ready")
	}
	// Check for expected ready confirmation header
	if readyStatus, ok := responseHeaders["x-stream-ready"]; ok {
		if len(readyStatus) > 0 && readyStatus[0] == "true" {
			return nil
		}
	}
	// No explicit rejection, passes by default in this test
	return nil
}

// testNonBlockingCredentials implements only PerRPCCredentials (not WaitForStreamFunctionalReady)
// for backward compatibility testing.
type testNonBlockingCredentials struct {
	token string
}

func (c *testNonBlockingCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + c.token}, nil
}

func (c *testNonBlockingCredentials) RequireTransportSecurity() bool {
	return false
}

func (s) TestWaitForStreamFunctionalReady_ImplementsInterface(t *testing.T) {
	// Test that testWaitForStreamFunctionalReady implements WaitForStreamFunctionalReady
	var _ WaitForStreamFunctionalReady = &testWaitForStreamFunctionalReady{}

	// Test that testNonBlockingCredentials implements PerRPCCredentials but NOT WaitForStreamFunctionalReady
	var _ PerRPCCredentials = &testNonBlockingCredentials{}

	// Verify that testNonBlockingCredentials does NOT implement WaitForStreamFunctionalReady
	creds := &testNonBlockingCredentials{token: "test-token"}
	_, ok := interface{}(creds).(WaitForStreamFunctionalReady)
	if ok {
		t.Fatal("testNonBlockingCredentials should not implement WaitForStreamFunctionalReady")
	}
}

func (s) TestWaitForStreamFunctionalReady_WaitForStreamFunctionalReady(t *testing.T) {
	testCases := []struct {
		name                       string
		waitForFunctionalReady     bool
		expectedWaitForFunctionalReady bool
	}{
		{
			name:                       "WaitForStreamFunctionalReady returns true",
			waitForFunctionalReady:     true,
			expectedWaitForFunctionalReady: true,
		},
		{
			name:                       "WaitForStreamFunctionalReady returns false",
			waitForFunctionalReady:     false,
			expectedWaitForFunctionalReady: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			creds := &testWaitForStreamFunctionalReady{
				token:                  "test-token",
				waitForFunctionalReady: tc.waitForFunctionalReady,
			}

			result := creds.WaitForStreamFunctionalReady()
			if result != tc.expectedWaitForFunctionalReady {
				t.Errorf("WaitForStreamFunctionalReady() = %v, want %v", result, tc.expectedWaitForFunctionalReady)
			}
			if !creds.waitForFunctionalReadyCalled {
				t.Error("WaitForStreamFunctionalReady was not called")
			}
		})
	}
}

func (s) TestWaitForStreamFunctionalReady_ValidateStreamFunctionalReady(t *testing.T) {
	testCases := []struct {
		name              string
		validateShouldPass bool
		responseHeaders   map[string][]string
		expectError       bool
	}{
		{
			name:              "Valid ready response with confirmation header",
			validateShouldPass: true,
			responseHeaders: map[string][]string{
				"x-stream-ready": {"true"},
			},
			expectError: false,
		},
		{
			name:              "Valid ready response without explicit confirmation",
			validateShouldPass: true,
			responseHeaders:   map[string][]string{},
			expectError:       false,
		},
		{
			name:              "Invalid ready response - server not ready",
			validateShouldPass: false,
			responseHeaders: map[string][]string{
				"x-stream-ready": {"false"},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			creds := &testWaitForStreamFunctionalReady{
				token:                  "test-token",
				waitForFunctionalReady: true,
				validateShouldPass:     tc.validateShouldPass,
			}

			err := creds.ValidateStreamFunctionalReady(tc.responseHeaders)

			if tc.expectError && err == nil {
				t.Error("ValidateStreamFunctionalReady() expected error, got nil")
			}
			if !tc.expectError && err != nil {
				t.Errorf("ValidateStreamFunctionalReady() unexpected error: %v", err)
			}
			if !creds.validateFunctionalReadyCalled {
				t.Error("ValidateStreamFunctionalReady was not called")
			}
		})
	}
}

func (s) TestWaitForStreamFunctionalReady_TypeAssertion(t *testing.T) {
	// Test type assertion from PerRPCCredentials to WaitForStreamFunctionalReady
	var baseCreds PerRPCCredentials = &testWaitForStreamFunctionalReady{
		token:                  "test-token",
		waitForFunctionalReady: true,
	}

	// Should be able to type assert to WaitForStreamFunctionalReady
	waitCreds, ok := baseCreds.(WaitForStreamFunctionalReady)
	if !ok {
		t.Fatal("Failed to type assert PerRPCCredentials to WaitForStreamFunctionalReady")
	}

	if !waitCreds.WaitForStreamFunctionalReady() {
		t.Error("WaitForStreamFunctionalReady() should return true")
	}

	// Test that non-blocking credentials cannot be type asserted
	var nonBlockingCreds PerRPCCredentials = &testNonBlockingCredentials{token: "test"}
	_, ok = nonBlockingCreds.(WaitForStreamFunctionalReady)
	if ok {
		t.Error("testNonBlockingCredentials should not be assertable to WaitForStreamFunctionalReady")
	}
}

func (s) TestWaitForStreamFunctionalReady_GetRequestMetadata(t *testing.T) {
	creds := &testWaitForStreamFunctionalReady{
		token:                  "my-jwt-token",
		waitForFunctionalReady: true,
	}

	ctx := context.Background()
	metadata, err := creds.GetRequestMetadata(ctx, "https://example.com")
	if err != nil {
		t.Fatalf("GetRequestMetadata failed: %v", err)
	}

	if !creds.getMetadataCalled {
		t.Error("GetRequestMetadata was not called")
	}

	expectedAuth := "Bearer my-jwt-token"
	if metadata["authorization"] != expectedAuth {
		t.Errorf("authorization header = %q, want %q", metadata["authorization"], expectedAuth)
	}
}

func (s) TestWaitForStreamFunctionalReady_RequireTransportSecurity(t *testing.T) {
	testCases := []struct {
		name                    string
		requireTransportSec     bool
		expectedTransportSec    bool
	}{
		{
			name:                 "Requires transport security",
			requireTransportSec:  true,
			expectedTransportSec: true,
		},
		{
			name:                 "Does not require transport security",
			requireTransportSec:  false,
			expectedTransportSec: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			creds := &testWaitForStreamFunctionalReady{
				token:               "test-token",
				requireTransportSec: tc.requireTransportSec,
			}

			result := creds.RequireTransportSecurity()
			if result != tc.expectedTransportSec {
				t.Errorf("RequireTransportSecurity() = %v, want %v", result, tc.expectedTransportSec)
			}
		})
	}
}
