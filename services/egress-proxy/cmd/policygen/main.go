// policygen is the only parser for the reviewed provider catalog. Release
// scripts call "plan" and pass its canonical selection and digest into Docker.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ai-gateway/egress-proxy/internal/egresspolicy"
)

const (
	catalogPath  = "providers/catalog.json"
	templatePath = "envoy.yaml.tmpl"
)

type providerFlags []string

func (values *providerFlags) String() string {
	return strings.Join(*values, ",")
}

func (values *providerFlags) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "policygen:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("use plan or generate")
	}
	switch arguments[0] {
	case "plan":
		return runPlan(arguments[1:])
	case "generate":
		return runGenerate(arguments[1:])
	case "normalize":
		return runNormalize(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q; use plan, generate, or normalize", arguments[0])
	}
}

func runNormalize(arguments []string) error {
	flags := flag.NewFlagSet("normalize", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var output string
	var epochText string
	flags.StringVar(&output, "output", "", "generated output directory")
	flags.StringVar(&epochText, "source-date-epoch", "", "nonnegative Unix timestamp")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || output == "" || !filepath.IsAbs(output) {
		return errors.New("normalize requires one absolute --output and no positional arguments")
	}
	epoch, err := strconv.ParseInt(epochText, 10, 64)
	if err != nil || epoch < 0 {
		return errors.New("--source-date-epoch must be a nonnegative integer")
	}
	return egresspolicy.NormalizeTimestamps(output, epoch)
}

func runPlan(arguments []string) error {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var providers providerFlags
	var providersCSV string
	flags.Var(&providers, "provider", "reviewed provider name; repeat for more than one")
	flags.StringVar(&providersCSV, "providers-csv", "", "canonical comma-separated provider names for build automation")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("plan accepts no positional arguments")
	}
	requested, canonicalCSV, err := requestedProviders(providers, providersCSV)
	if err != nil {
		return err
	}
	receipt, err := egresspolicy.Plan(catalogPath, ".", templatePath, requested, time.Now().UTC())
	if err != nil {
		return err
	}
	if canonicalCSV && providersCSV != strings.Join(receipt.SelectedProviders, ",") {
		return errors.New("--providers-csv must already be deduplicated and in canonical order")
	}
	return printReceipt(receipt)
}

func runGenerate(arguments []string) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var providers providerFlags
	var providersCSV string
	var output string
	var expectedPolicySHA256 string
	flags.Var(&providers, "provider", "reviewed provider name; repeat for more than one")
	flags.StringVar(&providersCSV, "providers-csv", "", "canonical comma-separated provider names for build automation")
	flags.StringVar(&output, "output", "", "empty output directory")
	flags.StringVar(&expectedPolicySHA256, "expect-policy-sha256", "", "digest returned by policygen plan")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("generate accepts no positional arguments")
	}
	if output == "" || !filepath.IsAbs(output) {
		return errors.New("--output must be an absolute path")
	}
	if expectedPolicySHA256 == "" {
		return errors.New("--expect-policy-sha256 is required")
	}
	requested, canonicalCSV, err := requestedProviders(providers, providersCSV)
	if err != nil {
		return err
	}
	plan, err := egresspolicy.Plan(catalogPath, ".", templatePath, requested, time.Now().UTC())
	if err != nil {
		return err
	}
	if canonicalCSV && providersCSV != strings.Join(plan.SelectedProviders, ",") {
		return errors.New("--providers-csv must already be deduplicated and in canonical order")
	}
	receipt, err := egresspolicy.Generate(
		catalogPath,
		".",
		templatePath,
		output,
		requested,
		expectedPolicySHA256,
		time.Now().UTC(),
	)
	if err != nil {
		return err
	}
	return printReceipt(receipt)
}

func requestedProviders(repeated providerFlags, csv string) ([]string, bool, error) {
	if len(repeated) > 0 && csv != "" {
		return nil, false, errors.New("use repeated --provider or --providers-csv, not both")
	}
	if csv != "" {
		return strings.Split(csv, ","), true, nil
	}
	if len(repeated) == 0 {
		return nil, false, errors.New("select at least one --provider")
	}
	return repeated, false, nil
}

func printReceipt(receipt egresspolicy.Receipt) error {
	content, err := egresspolicy.CanonicalReceiptBytes(receipt)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(content)
	return err
}
