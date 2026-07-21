package egresspolicy

const (
	CatalogSchemaVersion = 1
	PolicySchemaVersion  = 1
)

// Catalog is the reviewed build-time allow-list. It is never copied into the
// runtime image.
type Catalog struct {
	SchemaVersion int               `json:"schema_version"`
	Providers     []CatalogProvider `json:"providers"`
}

type CatalogProvider struct {
	Name                 string   `json:"name"`
	APIHostname          string   `json:"api_hostname"`
	RoutePrefix          string   `json:"route_prefix"`
	SNI                  string   `json:"sni"`
	ExactSANs            []string `json:"exact_sans"`
	CABundle             string   `json:"ca_bundle"`
	CABundleSHA256       string   `json:"ca_bundle_sha256"`
	CASHA256Fingerprints []string `json:"ca_sha256_fingerprints"`
	ProvenanceFile       string   `json:"provenance_file"`
	ProvenanceSHA256     string   `json:"provenance_sha256"`
	bundleBytes          []byte
}

// RuntimePolicy is the selected policy baked into one Envoy image. It contains
// no unselected provider and no source path from the build catalog.
type RuntimePolicy struct {
	SchemaVersion     int               `json:"schema_version"`
	SelectedProviders []string          `json:"selected_providers"`
	Providers         []RuntimeProvider `json:"providers"`
	EnvoyConfigSHA256 string            `json:"envoy_config_sha256"`
}

type RuntimeProvider struct {
	Name                 string   `json:"name"`
	APIHostname          string   `json:"api_hostname"`
	RoutePrefix          string   `json:"route_prefix"`
	SNI                  string   `json:"sni"`
	ExactSANs            []string `json:"exact_sans"`
	CAFile               string   `json:"ca_file"`
	CABundleSHA256       string   `json:"ca_bundle_sha256"`
	CASHA256Fingerprints []string `json:"ca_sha256_fingerprints"`
	ProvenanceSHA256     string   `json:"provenance_sha256"`
}

// Receipt is safe, non-secret evidence for the release manifest and deploy
// checks. The image ID is added by the release layer after Docker builds it.
type Receipt struct {
	SchemaVersion      int               `json:"schema_version"`
	EgressPolicySHA256 string            `json:"egress_policy_sha256"`
	EnvoyConfigSHA256  string            `json:"envoy_config_sha256"`
	SelectedProviders  []string          `json:"selected_providers"`
	Providers          []RuntimeProvider `json:"providers"`
}

type Provenance struct {
	SchemaVersion                 int      `json:"schema_version"`
	Provider                      string   `json:"provider"`
	APIHostname                   string   `json:"api_hostname"`
	VerificationStatus            string   `json:"verification_status"`
	VerifiedAt                    string   `json:"verified_at"`
	VerificationScope             string   `json:"verification_scope"`
	SourceBundleSHA256            string   `json:"source_bundle_sha256"`
	CertificateSHA256Fingerprints []string `json:"certificate_sha256_fingerprints"`
	Verification                  []string `json:"verification"`
	Limitations                   []string `json:"limitations"`
}

type InstallPaths struct {
	Policy       string
	PolicyDigest string
	Receipt      string
	Config       string
	CertDir      string
}
