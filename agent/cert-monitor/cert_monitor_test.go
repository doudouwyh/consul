package certmon

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/consul/agent/cache"
	cachetype "github.com/hashicorp/consul/agent/cache-types"
	"github.com/hashicorp/consul/agent/connect"
	"github.com/hashicorp/consul/agent/structs"
	"github.com/hashicorp/consul/agent/token"
	"github.com/hashicorp/consul/sdk/testutil"
	"github.com/hashicorp/consul/tlsutil"
	"github.com/hashicorp/go-uuid"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type mockCache struct {
	mock.Mock
}

func (m *mockCache) Notify(ctx context.Context, t string, r cache.Request, correlationID string, ch chan<- cache.UpdateEvent) error {
	ret := m.Called(t, r, correlationID)
	return ret.Error(0)
}

func (m *mockCache) Prepopulate(t string, result cache.FetchResult, dc string, token string, key string) error {
	ret := m.Called(t, result, dc, token, key)
	return ret.Error(0)
}

func testTLSConfigurator(t *testing.T) *tlsutil.Configurator {
	t.Helper()
	logger := testutil.Logger(t)
	cfg, err := tlsutil.NewConfigurator(tlsutil.Config{AutoEncryptTLS: true}, logger)
	require.NoError(t, err)
	return cfg
}

func newLeaf(t *testing.T, ca *structs.CARoot, idx uint64, expiration time.Duration) *structs.IssuedCert {
	t.Helper()

	pub, priv, err := connect.TestAgentLeaf(t, "node", "foo", ca, expiration)
	require.NoError(t, err)
	cert, err := connect.ParseCert(pub)
	require.NoError(t, err)

	spiffeID, err := connect.ParseCertURI(cert.URIs[0])
	require.NoError(t, err)

	agentID, ok := spiffeID.(*connect.SpiffeIDAgent)
	require.True(t, ok, "certificate doesn't have an agent leaf cert URI")

	return &structs.IssuedCert{
		SerialNumber:   cert.SerialNumber.String(),
		CertPEM:        pub,
		PrivateKeyPEM:  priv,
		ValidAfter:     cert.NotBefore,
		ValidBefore:    cert.NotAfter,
		Agent:          agentID.Agent,
		AgentURI:       agentID.URI().String(),
		EnterpriseMeta: *structs.DefaultEnterpriseMeta(),
		RaftIndex: structs.RaftIndex{
			CreateIndex: idx,
			ModifyIndex: idx,
		},
	}
}

type fallbackChan chan *structs.SignedResponse

func (f fallbackChan) fallback(_ context.Context) (*structs.SignedResponse, error) {
	select {
	case resp := <-f:
		return resp, nil
	default:
		return nil, fmt.Errorf("No response was ready")
	}
}

type testCertMonitor struct {
	monitor  *CertMonitor
	mcache   *mockCache
	tls      *tlsutil.Configurator
	tokens   *token.Store
	fallback fallbackChan

	extraCACerts []string
	initialCert  *structs.IssuedCert
	initialRoots *structs.IndexedCARoots

	// these are some variables that the CertMonitor was created with
	datacenter           string
	nodeName             string
	dns                  []string
	ips                  []net.IP
	verifyServerHostname bool
}

func newTestCertMonitor(t *testing.T) testCertMonitor {
	t.Helper()

	tlsConfigurator := testTLSConfigurator(t)
	tokens := new(token.Store)

	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	tokens.UpdateAgentToken(id, token.TokenSourceConfig)

	ca := connect.TestCA(t, nil)
	manualCA := connect.TestCA(t, nil)
	// this cert is setup to not expire quickly. this will prevent
	// the test from accidentally running the fallback routine
	// before we want to force that to happen.
	issued := newLeaf(t, ca, 1, 10*time.Minute)

	indexedRoots := structs.IndexedCARoots{
		ActiveRootID: ca.ID,
		TrustDomain:  connect.TestClusterID,
		Roots: []*structs.CARoot{
			ca,
		},
		QueryMeta: structs.QueryMeta{
			Index: 1,
		},
	}

	initialCerts := &structs.SignedResponse{
		ConnectCARoots:       indexedRoots,
		IssuedCert:           *issued,
		ManualCARoots:        []string{manualCA.RootCert},
		VerifyServerHostname: true,
	}

	dnsSANs := []string{"test.dev"}
	ipSANs := []net.IP{net.IPv4(198, 18, 0, 1)}

	fallback := make(fallbackChan)

	mcache := &mockCache{}
	rootRes := cache.FetchResult{Value: &indexedRoots, Index: 1}
	rootsReq := structs.DCSpecificRequest{Datacenter: "foo"}
	mcache.On("Prepopulate", cachetype.ConnectCARootName, rootRes, "foo", "", rootsReq.CacheInfo().Key).Return(nil)

	leafReq := cachetype.ConnectCALeafRequest{
		Token:      tokens.AgentToken(),
		Agent:      "node",
		Datacenter: "foo",
		DNSSAN:     dnsSANs,
		IPSAN:      ipSANs,
	}
	leafRes := cache.FetchResult{
		Value: issued,
		Index: 1,
		State: cachetype.ConnectCALeafSuccess(ca.SigningKeyID),
	}
	mcache.On("Prepopulate", cachetype.ConnectCALeafName, leafRes, "foo", tokens.AgentToken(), leafReq.Key()).Return(nil)

	// we can assert more later but this should always be done.
	defer mcache.AssertExpectations(t)

	monitor, err := New(
		WithCache(mcache),
		WithLogger(testutil.Logger(t)),
		WithTLSConfigurator(tlsConfigurator),
		WithTokens(tokens),
		WithFallback(fallback.fallback),
		WithDNSSANs(dnsSANs),
		WithIPSANs(ipSANs),
		WithDatacenter("foo"),
		WithNodeName("node"),
		WithInitialCerts(initialCerts),
	)
	require.NoError(t, err)
	require.NotNil(t, monitor)

	return testCertMonitor{
		monitor:              monitor,
		tls:                  tlsConfigurator,
		tokens:               tokens,
		mcache:               mcache,
		fallback:             fallback,
		extraCACerts:         []string{manualCA.RootCert},
		initialCert:          issued,
		initialRoots:         &indexedRoots,
		datacenter:           "foo",
		nodeName:             "node",
		dns:                  dnsSANs,
		ips:                  ipSANs,
		verifyServerHostname: true,
	}
}

// convenience method to get a TLS Certificate from the intial issued certificate and priv key
func (cm *testCertMonitor) initialTLSCertificate(t *testing.T) *tls.Certificate {
	t.Helper()

	cert, err := tls.X509KeyPair([]byte(cm.initialCert.CertPEM), []byte(cm.initialCert.PrivateKeyPEM))
	require.NoError(t, err)
	return &cert
}

// just a convenience method to get a list of all the CA pems that we set up regardless
// of manual vs connect.
func (cm *testCertMonitor) initialCACerts() []string {
	pems := cm.extraCACerts
	for _, root := range cm.initialRoots.Roots {
		pems = append(pems, root.RootCert)
	}
	return pems
}

func TestCertMonitor_InitialCerts(t *testing.T) {
	// this also ensures that the cache was prepopulated properly
	cm := newTestCertMonitor(t)

	// verify that the certificate was injected into the TLS configurator correctly
	require.Equal(t, cm.initialTLSCertificate(t), cm.tls.Cert())
	// verify that the CA certs (both Connect and manual ones) were injected correctly
	require.ElementsMatch(t, cm.initialCACerts(), cm.tls.CAPems())
	// verify that the auto-tls verify server hostname setting was injected correctly
	require.Equal(t, cm.verifyServerHostname, cm.tls.VerifyServerHostname())
}

func TestCertMonitor_GoRoutineManagement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cm := newTestCertMonitor(t)

	// ensure that the monitor is not running
	require.False(t, cm.monitor.IsRunning())

	// ensure that nothing bad happens and that it reports as stopped
	require.False(t, cm.monitor.Stop())

	// we will never send notifications so these just ignore everything
	cm.mcache.On("Notify", cachetype.ConnectCARootName, &structs.DCSpecificRequest{Datacenter: cm.datacenter}, rootsWatchID).Return(nil)
	cm.mcache.On("Notify", cachetype.ConnectCALeafName,
		&cachetype.ConnectCALeafRequest{
			Token:      cm.tokens.AgentToken(),
			Datacenter: cm.datacenter,
			Agent:      cm.nodeName,
			DNSSAN:     cm.dns,
			IPSAN:      cm.ips,
		},
		leafWatchID,
	).Return(nil).Times(2)

	require.NoError(t, cm.monitor.Start(ctx))
	require.True(t, cm.monitor.IsRunning())
	testutil.RequireErrorContains(t, cm.monitor.Start(ctx), "the CertMonitor is already running")
	require.True(t, cm.monitor.Stop())
	require.Eventually(t, func() bool { return !cm.monitor.IsRunning() }, 100*time.Millisecond, time.Millisecond)
	require.NoError(t, cm.monitor.Start(ctx))

	// ensure that context cancellation causes us to stop as well
	cancel()
	require.Eventually(t, func() bool { return !cm.monitor.IsRunning() }, 100*time.Millisecond, time.Millisecond)

	cm.mcache.AssertExpectations(t)
}

func TestCertMonitor_New_Errors(t *testing.T) {
	type testCase struct {
		cfg []Config
		err string
	}

	fallback := func(_ context.Context) (*structs.SignedResponse, error) {
		return nil, fmt.Errorf("Unimplemented")
	}

	tokens := new(token.Store)

	cases := map[string]testCase{
		"no-cache": {
			cfg: []Config{
				WithTLSConfigurator(testTLSConfigurator(t)),
				WithFallback(fallback),
				WithTokens(tokens),
				WithDatacenter("foo"),
				WithNodeName("bar"),
				WithInitialCerts(&structs.SignedResponse{}),
			},
			err: "CertMonitor creation requires a Cache",
		},
		"no-tls-configurator": {
			cfg: []Config{
				WithCache(cache.New(nil)),
				WithFallback(fallback),
				WithTokens(tokens),
				WithDatacenter("foo"),
				WithNodeName("bar"),
				WithInitialCerts(&structs.SignedResponse{}),
			},
			err: "CertMonitor creation requires a TLS Configurator",
		},
		"no-fallback": {
			cfg: []Config{
				WithCache(cache.New(nil)),
				WithTLSConfigurator(testTLSConfigurator(t)),
				// WithFallback(fallback),
				WithTokens(tokens),
				WithDatacenter("foo"),
				WithNodeName("bar"),
				WithInitialCerts(&structs.SignedResponse{}),
			},
			err: "CertMonitor creation requires specifying a FallbackFunc",
		},
		"no-tokens": {
			cfg: []Config{
				WithCache(cache.New(nil)),
				WithTLSConfigurator(testTLSConfigurator(t)),
				WithFallback(fallback),
				WithDatacenter("foo"),
				WithNodeName("bar"),
				WithInitialCerts(&structs.SignedResponse{}),
			},
			err: "CertMonitor creation requires specifying a token store",
		},
		"no-datacenter": {
			cfg: []Config{
				WithCache(cache.New(nil)),
				WithTLSConfigurator(testTLSConfigurator(t)),
				WithFallback(fallback),
				WithTokens(tokens),
				WithNodeName("bar"),
				WithInitialCerts(&structs.SignedResponse{}),
			},
			err: "CertMonitor creation requires specifying the datacenter",
		},
		"no-node-name": {
			cfg: []Config{
				WithCache(cache.New(nil)),
				WithTLSConfigurator(testTLSConfigurator(t)),
				WithFallback(fallback),
				WithTokens(tokens),
				WithDatacenter("foo"),
				WithInitialCerts(&structs.SignedResponse{}),
			},
			err: "CertMonitor creation requires specifying the agent's node name",
		},
	}

	for name, tcase := range cases {
		t.Run(name, func(t *testing.T) {
			monitor, err := New(tcase.cfg...)
			testutil.RequireErrorContains(t, err, tcase.err)
			require.Nil(t, monitor)
		})
	}
}
