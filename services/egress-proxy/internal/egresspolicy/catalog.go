package egresspolicy

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func LoadCatalog(catalogPath, componentRoot string, now time.Time) (Catalog, error) {
	content, err := readRegularBounded(catalogPath, maxCatalogBytes)
	if err != nil {
		return Catalog{}, fmt.Errorf("read provider catalog: %w", err)
	}
	var catalog Catalog
	if err := decodeStrictJSON(content, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode provider catalog: %w", err)
	}
	if catalog.SchemaVersion != CatalogSchemaVersion {
		return Catalog{}, fmt.Errorf("provider catalog schema must be %d", CatalogSchemaVersion)
	}
	if len(catalog.Providers) == 0 {
		return Catalog{}, errors.New("provider catalog is empty")
	}

	names := make(map[string]struct{}, len(catalog.Providers))
	hostnames := make(map[string]struct{}, len(catalog.Providers))
	routes := make(map[string]struct{}, len(catalog.Providers))
	provenanceFiles := make(map[string]struct{}, len(catalog.Providers))
	previousName := ""
	for index := range catalog.Providers {
		provider := &catalog.Providers[index]
		if previousName != "" && provider.Name <= previousName {
			return Catalog{}, errors.New("provider catalog entries must be sorted by unique name")
		}
		previousName = provider.Name
		if err := validateCatalogProvider(provider); err != nil {
			return Catalog{}, fmt.Errorf("provider %q: %w", provider.Name, err)
		}
		if _, found := names[provider.Name]; found {
			return Catalog{}, fmt.Errorf("duplicate provider name %q", provider.Name)
		}
		if _, found := hostnames[provider.APIHostname]; found {
			return Catalog{}, fmt.Errorf("duplicate provider hostname %q", provider.APIHostname)
		}
		if _, found := routes[provider.RoutePrefix]; found {
			return Catalog{}, fmt.Errorf("duplicate provider route %q", provider.RoutePrefix)
		}
		if _, found := provenanceFiles[provider.ProvenanceFile]; found {
			return Catalog{}, fmt.Errorf("duplicate provenance file %q", provider.ProvenanceFile)
		}
		names[provider.Name] = struct{}{}
		hostnames[provider.APIHostname] = struct{}{}
		routes[provider.RoutePrefix] = struct{}{}
		provenanceFiles[provider.ProvenanceFile] = struct{}{}

		bundlePath, err := joinInside(componentRoot, provider.CABundle)
		if err != nil {
			return Catalog{}, fmt.Errorf("provider %q CA bundle: %w", provider.Name, err)
		}
		provider.bundleBytes, err = readRegularBounded(bundlePath, maxBundleBytes)
		if err != nil {
			return Catalog{}, fmt.Errorf("read provider %q CA bundle: %w", provider.Name, err)
		}
		if err := validateBundle(
			provider.bundleBytes,
			provider.CABundleSHA256,
			provider.CASHA256Fingerprints,
			now,
		); err != nil {
			return Catalog{}, fmt.Errorf("provider %q CA bundle: %w", provider.Name, err)
		}
		if err := validateProvenance(*provider, componentRoot); err != nil {
			return Catalog{}, err
		}
	}
	for left := range catalog.Providers {
		for right := left + 1; right < len(catalog.Providers); right++ {
			leftRoute := catalog.Providers[left].RoutePrefix
			rightRoute := catalog.Providers[right].RoutePrefix
			if strings.HasPrefix(leftRoute, rightRoute) || strings.HasPrefix(rightRoute, leftRoute) {
				return Catalog{}, fmt.Errorf("provider routes %q and %q overlap", leftRoute, rightRoute)
			}
		}
	}
	return catalog, nil
}

func validateCatalogProvider(provider *CatalogProvider) error {
	if !validProviderName(provider.Name) {
		return errors.New("name must be lowercase letters, digits, or interior hyphens")
	}
	if !validHostname(provider.APIHostname) {
		return errors.New("API hostname must be an exact lowercase DNS name")
	}
	if !validRoutePrefix(provider.RoutePrefix) {
		return errors.New("route prefix must be a safe absolute path ending in a slash")
	}
	if !validHostname(provider.SNI) {
		return errors.New("SNI must be an exact lowercase DNS name")
	}
	if !isSortedUnique(provider.ExactSANs) {
		return errors.New("exact SANs must be nonempty, sorted, and unique")
	}
	sniFound := false
	for _, san := range provider.ExactSANs {
		if !validHostname(san) {
			return fmt.Errorf("invalid exact SAN %q", san)
		}
		if san == provider.SNI {
			sniFound = true
		}
	}
	if !sniFound {
		return errors.New("SNI must appear in the exact SAN list")
	}
	if !safeRelativePath(provider.CABundle) || filepath.Ext(provider.CABundle) != ".pem" {
		return errors.New("CA bundle must be a safe relative .pem path from the component root")
	}
	if !validSHA256(provider.CABundleSHA256) {
		return errors.New("CA bundle SHA-256 must be 64 lowercase hexadecimal characters")
	}
	if len(provider.CASHA256Fingerprints) == 0 {
		return errors.New("CA certificate fingerprint list is empty")
	}
	fingerprints := make(map[string]struct{}, len(provider.CASHA256Fingerprints))
	for _, fingerprint := range provider.CASHA256Fingerprints {
		if !validSHA256(fingerprint) {
			return fmt.Errorf("invalid CA certificate fingerprint %q", fingerprint)
		}
		if _, found := fingerprints[fingerprint]; found {
			return errors.New("CA certificate fingerprint list contains a duplicate")
		}
		fingerprints[fingerprint] = struct{}{}
	}
	if !safeRelativePath(provider.ProvenanceFile) || filepath.Ext(provider.ProvenanceFile) != ".json" {
		return errors.New("provenance file must be a safe relative .json path")
	}
	if !validSHA256(provider.ProvenanceSHA256) {
		return errors.New("provenance SHA-256 must be 64 lowercase hexadecimal characters")
	}
	return nil
}

func validateProvenance(provider CatalogProvider, componentRoot string) error {
	path, err := joinInside(componentRoot, provider.ProvenanceFile)
	if err != nil {
		return fmt.Errorf("provider %q provenance: %w", provider.Name, err)
	}
	content, err := readRegularBounded(path, maxProvenanceBytes)
	if err != nil {
		return fmt.Errorf("read provider %q provenance: %w", provider.Name, err)
	}
	if sha256Hex(content) != provider.ProvenanceSHA256 {
		return fmt.Errorf("provider %q provenance SHA-256 does not match the catalog", provider.Name)
	}
	var provenance Provenance
	if err := decodeStrictJSON(content, &provenance); err != nil {
		return fmt.Errorf("decode provider %q provenance: %w", provider.Name, err)
	}
	if provenance.SchemaVersion != 1 || provenance.Provider != provider.Name ||
		provenance.APIHostname != provider.APIHostname ||
		provenance.VerificationStatus != "current-chain-verified" ||
		provenance.VerifiedAt == "" || provenance.VerificationScope == "" ||
		provenance.SourceBundleSHA256 != provider.CABundleSHA256 ||
		!equalStrings(provenance.CertificateSHA256Fingerprints, provider.CASHA256Fingerprints) ||
		len(provenance.Verification) == 0 || len(provenance.Limitations) == 0 {
		return fmt.Errorf("provider %q provenance does not match its approved catalog entry", provider.Name)
	}
	if _, err := time.Parse("2006-01-02", provenance.VerifiedAt); err != nil {
		return fmt.Errorf("provider %q provenance has an invalid verification date", provider.Name)
	}
	return nil
}

// SelectProviders validates names against the reviewed catalog, removes exact
// duplicates, and returns providers in canonical name order.
func SelectProviders(catalog Catalog, requested []string) ([]CatalogProvider, error) {
	if len(requested) == 0 {
		return nil, errors.New("select at least one provider")
	}
	approved := make(map[string]CatalogProvider, len(catalog.Providers))
	for _, provider := range catalog.Providers {
		approved[provider.Name] = provider
	}
	selectedNames := make(map[string]struct{}, len(requested))
	for _, name := range requested {
		if name == "" || strings.TrimSpace(name) != name || !validProviderName(name) {
			return nil, fmt.Errorf("invalid provider name %q", name)
		}
		if _, found := approved[name]; !found {
			return nil, fmt.Errorf("provider %q is not in the reviewed catalog", name)
		}
		selectedNames[name] = struct{}{}
	}
	names := make([]string, 0, len(selectedNames))
	for name := range selectedNames {
		names = append(names, name)
	}
	sort.Strings(names)
	selected := make([]CatalogProvider, 0, len(names))
	for _, name := range names {
		selected = append(selected, approved[name])
	}
	return selected, nil
}
