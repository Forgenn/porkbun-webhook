package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/nrdcg/porkbun"
	zap "go.uber.org/zap"
	v1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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
		&porkbunDNSProviderSolver{},
	)
}

// porkbunDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type porkbunDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client kubernetes.Clientset
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
type customDNSProviderConfig struct {
	// Important, these JSON tag names must match the ones in testdata to be correctly parsed!
	APIKeySecretRef       v1.SecretKeySelector `json:"apiKeySecretRef"`
	SecretAPIKeySecretRef v1.SecretKeySelector `json:"secretKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *porkbunDNSProviderSolver) Name() string {
	return "porkbun-solver"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *porkbunDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	zap.S().Infof("Running Challenge request with FQDN %s and ResolvedZone %s", ch.ResolvedFQDN, ch.ResolvedZone)

	porkbunClient, err := c.loadConfig(ch.Config, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	ctx := context.Background()

	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	subdomain := strings.TrimSuffix(ch.ResolvedFQDN, "."+domain+".")
	fdqn := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	value, ID, err := c.checkRecordExistance(ctx, *porkbunClient, domain, fdqn, "TXT")

	if err != nil {
		return err
	}

	if value == "" && ID == "" {
		_, err := porkbunClient.CreateRecord(ctx, domain, porkbun.Record{
			Name:    subdomain,
			Type:    "TXT",
			Content: ch.Key,
			TTL:     "60",
		})

		if err != nil {
			return errors.Wrap(err, "Error creating the record")
		}

		zap.S().Infof("Succesfully created record %s.%s", subdomain, domain)
	}

	if value != "" && ID != "" {
		RecordId, err := strconv.Atoi(ID)
		if err != nil {
			return errors.Wrap(err, "couldn't cast record it to int")
		}

		err = porkbunClient.EditRecord(ctx, domain, RecordId, porkbun.Record{
			Name:    subdomain,
			Type:    "TXT",
			Content: ch.Key,
			TTL:     "60",
		})

		if err != nil {
			return errors.Wrap(err, "Error editing record")
		}

	}

	if err != nil {
		zap.S().Info("error pinging", err)
		panic(err)
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *porkbunDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	zap.S().Infof("Running Challenge CleanUp request with FQDN %s and ResolvedZone %s", ch.ResolvedFQDN, ch.ResolvedZone)

	porkbunClient, err := c.loadConfig(ch.Config, ch.ResourceNamespace)

	ctx := context.Background()

	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	fdqn := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	_, ID, err := c.checkRecordExistance(ctx, *porkbunClient, domain, fdqn, "TXT")

	recordId, err := strconv.Atoi(ID)
	if err != nil {
		return errors.Wrap(err, "couldn't cast record it to int")
	}

	err = porkbunClient.DeleteRecord(ctx, domain, recordId)

	if err != nil {
		return err
	}

	zap.S().Infof("Succesfully deleted record %s", fdqn)

	return nil
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
func (c *porkbunDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = *cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

func (c *porkbunDNSProviderSolver) getSecretValueFromRef(secretRef v1.SecretKeySelector, namespace string) (string, error) {
	secret, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secretRef.Name, metav1.GetOptions{})

	if err != nil {
		return "", errors.Wrapf(err, "error retrieving secret %s from namespace %s", secretRef.Name, namespace)
	}

	var secretValue []byte
	var ok bool

	if secretValue, ok = secret.Data[secretRef.Key]; !ok {
		return "", errors.Wrapf(err, "error retrieving key %s from secret %s from namespace %s", secretRef.Key, secretRef.Name, namespace)
	}

	return string(secretValue), nil
}

// Check if a record of a certain type exists
// Return the value of the record, empty if error or if record not found, and the ID of the record.
func (c *porkbunDNSProviderSolver) checkRecordExistance(ctx context.Context, porkbunClient porkbun.Client, domain string, name string, recordType string) (string, string, error) {
	records, err := porkbunClient.RetrieveRecords(ctx, domain)

	if err != nil {
		return "", "", err
	}

	for _, record := range records {
		if record.Name == name && record.Type == recordType {
			return record.Content, record.ID, nil
		}
	}

	return "", "", nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func (c *porkbunDNSProviderSolver) loadConfig(cfgJSON *extapi.JSON, namespace string) (*porkbun.Client, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return nil, fmt.Errorf("no configuration provided")
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return nil, fmt.Errorf("error decoding solver config: %v", err)
	}

	secretAPIKey, err := c.getSecretValueFromRef(cfg.SecretAPIKeySecretRef, namespace)

	if err != nil {
		return nil, errors.Wrap(err, "error loading config")
	}

	apiKey, err := c.getSecretValueFromRef(cfg.APIKeySecretRef, namespace)

	if err != nil {
		return nil, errors.Wrap(err, "error loading config")
	}

	client := porkbun.New(secretAPIKey, apiKey)

	return client, nil
}

func New() webhook.Solver {
	zap.S().Info("INITTITNT\n\n\n\n\n")
	return &porkbunDNSProviderSolver{}
}
