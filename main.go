package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/api/cis/cisv1"
	"github.com/IBM-Cloud/bluemix-go/session"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	certmanagerv1 "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&cisProviderSolver{},
	)
}

// cisProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type cisProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type cisProviderConfig struct {
	CRN             string                          `json:"crn"`
	APIKeySecretRef certmanagerv1.SecretKeySelector `json:"apiKeySecretRef"`

	// +optional
	Timeout int `json:"timeout"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *cisProviderSolver) Name() string {
	return "cis"
}

func (c *cisProviderSolver) validate(cfg *cisProviderConfig) error {
	// Try to load the API key
	if cfg.APIKeySecretRef.LocalObjectReference.Name == "" {
		return errors.New("No API key provided")
	}

	return nil
}

func (c *cisProviderSolver) cisClient(cfg *cisProviderConfig, namespace string) (cisv1.CisServiceAPI, error) {
	if err := c.validate(cfg); err != nil {
		return nil, err
	}

	sec, err := c.client.CoreV1().Secrets(namespace).Get(cfg.APIKeySecretRef.LocalObjectReference.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	secBytes, ok := sec.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return nil, fmt.Errorf("Key %q not found in secret \"%s/%s\"", cfg.APIKeySecretRef.Key, cfg.APIKeySecretRef.LocalObjectReference.Name, namespace)
	}

	apiKey := string(secBytes)

	if cfg.Timeout == 0 {
		cfg.Timeout = 30
	}

	// Create provider
	sess, err := session.New(&bluemix.Config{
		BluemixAPIKey: apiKey,
		HTTPClient: &http.Client{
			Timeout: time.Duration(cfg.Timeout) * time.Second,
		},
	})

	if err != nil {
		return nil, err
	}

	return cisv1.New(sess)
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *cisProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	client, err := c.cisClient(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	zone, err := findZone(client, cfg.CRN, ch.ResolvedZone[:len(ch.ResolvedZone)-1])
	if err != nil {
		return err
	}

	_, err = client.Dns().CreateDns(cfg.CRN, zone.Id, cisv1.DnsBody{
		Name:    ch.ResolvedFQDN[:len(ch.ResolvedFQDN)-1],
		DnsType: "TXT",
		Content: ch.Key,
	})
	return err
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *cisProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	client, err := c.cisClient(&cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	zone, err := findZone(client, cfg.CRN, ch.ResolvedZone[:len(ch.ResolvedZone)-1])
	if err != nil {
		return err
	}

	record, err := findRecord(client, cfg.CRN, zone.Id, ch.ResolvedFQDN[:len(ch.ResolvedFQDN)-1], "TXT", ch.Key)
	if err != nil {
		return err
	}
	return client.Dns().DeleteDns(cfg.CRN, zone.Id, record.Id)
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *cisProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (cisProviderConfig, error) {
	cfg := cisProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
