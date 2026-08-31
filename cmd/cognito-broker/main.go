// Command cognito-broker mints an AWS Cognito access token for
// integration tests, from coordinates held in AWS Systems Manager.
//
//	cognito-broker              → JSON: token, expiry, non-secret profile
//	cognito-broker --format raw → the token alone
//
// It takes an ORDINARY AWS session — a named profile, or whatever the
// default chain resolves — and nothing else. That is the whole design:
// wherever an AWS call already works, this works, with no second
// credential, no second login and no service in the path.
//
// The consequence worth stating is that local and CI runs are the same
// command. They differ only in how the AWS session is obtained, which is
// a question the AWS chain already answers — a credential_process on a
// laptop, a pod identity or an assumed role in CI. A suite that passes
// locally therefore exercised the same path CI will.
//
// Why a binary rather than a library: the suites that need this are
// written in different languages. One binary they all shell out to is
// one implementation; a library would be three, and three drift.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"gopkg.in/yaml.v3"

	"github.com/truvity/cognito-broker/pkg/cognito"
	"github.com/truvity/cognito-broker/pkg/profile"
	"github.com/truvity/cognito-broker/pkg/tenant"
)

// configName is the file looked for, walking up from the working
// directory. Walking up rather than requiring an exact path means a
// recipe run from a package subdirectory finds the repository's config
// without every caller passing --config.
const configName = ".cognito-broker.yaml"

const defaultTimeout = 60 * time.Second

// config is the repository-committed half of the arrangement, and it is
// deliberately tiny.
//
// It holds no role and no account. Those live in aws.ini, which already
// carries them per face and is typically under CODEOWNERS precisely
// because widening what CI may reach needs review. Naming a role here
// would be a second way to grant AWS reach that routes around that
// review.
//
// `profile` is a SELECTOR, not a grant: it says which identity aws.ini
// already defines to use. It is named here rather than left to the
// caller's AWS_PROFILE because the choice belongs to the repository —
// and because a CI default profile is often deliberately something else,
// such as the runner's own pod identity, which cannot read the tree.
type config struct {
	Token struct {
		Region  string `yaml:"region"`
		Profile string `yaml:"profile"`
		Path    string `yaml:"path"`

		// Tenants names the isolated worlds the suite wants. The tool
		// generates a fresh id per name per run, because the platform
		// creates tenants lazily from the header and stores nothing in
		// advance -- so a new id IS a new empty tenant, and reusing one
		// would let a previous run's leftovers decide this run's result.
		Tenants []string `yaml:"tenants"`
	} `yaml:"token"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "cognito-broker:", err)
		os.Exit(1)
	}
}

func run(argv []string) error {
	fs := flag.NewFlagSet("cognito-broker", flag.ExitOnError)
	configPath := fs.String("config", "", "config file (default: nearest "+configName+" walking up from the working directory)")
	path := fs.String("path", "", "SSM parameter path holding the profile (overrides config)")
	region := fs.String("region", "", "AWS region (overrides config)")
	awsProfile := fs.String("profile", "", "AWS profile to resolve credentials with (overrides config)")
	format := fs.String("format", "json", "output format: json or raw")
	output := fs.String("output", "-", "write to this file instead of stdout (- means stdout)")
	tenants := fs.String("tenants", "", "comma-separated tenant names to generate ids for (overrides config)")

	if err := fs.Parse(argv); err != nil {
		return err
	}

	if *format != "json" && *format != "raw" {
		return fmt.Errorf("--format must be json or raw, got %q", *format)
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	ssmPath := pick(*path, cfg.Token.Path)
	if ssmPath == "" {
		return errors.New("no SSM path: set token.path in " + configName + " or pass --path")
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	opts := []func(*awsconfig.LoadOptions) error{}

	if r := pick(*region, cfg.Token.Region); r != "" {
		opts = append(opts, awsconfig.WithRegion(r))
	}

	if p := pick(*awsProfile, cfg.Token.Profile); p != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(p))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return fmt.Errorf("aws config: %w", err)
	}

	prof, err := profile.Read(ctx, ssm.NewFromConfig(awsCfg), ssmPath)
	if err != nil {
		return err
	}

	if err := prof.Validate(); err != nil {
		return err
	}

	tok, err := cognito.Exchange(ctx, nil,
		prof["token_url"], prof["client_id"], prof["client_secret"], prof.Scopes())
	if err != nil {
		return err
	}

	out, closeOut, err := openOutput(*output)
	if err != nil {
		return err
	}

	defer closeOut()

	if *format == "raw" {
		_, err := fmt.Fprintln(out, tok.AccessToken)

		return err
	}

	names := tenant.ParseNames(*tenants)
	if len(names) == 0 {
		names = cfg.Token.Tenants
	}

	ids, err := tenant.Generate(names)
	if err != nil {
		return err
	}

	body := map[string]any{
		"access_token": tok.AccessToken,
		"token_type":   tok.TokenType,
		"expires_at":   time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).UTC().Format(time.RFC3339),
		"profile":      prof.Public(),
	}

	// Omitted entirely rather than emitted empty: a consumer that does
	// not ask for tenants should not have to distinguish "none asked
	// for" from "asked and got none".
	if len(ids) > 0 {
		body["tenants"] = ids
	}

	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")

	return enc.Encode(body)
}

// pick returns the first non-empty value, which is the precedence order
// flags-then-config written once.
func pick(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}

	return ""
}

// loadConfig reads the explicit path, or the nearest configName walking
// up from the working directory. A missing file is not an error: every
// value it would carry can also be given as a flag.
func loadConfig(explicit string) (*config, error) {
	var cfg config

	path := explicit
	if path == "" {
		found, err := findConfig()
		if err != nil {
			return nil, err
		}

		if found == "" {
			return &cfg, nil
		}

		path = found
	}

	raw, err := os.ReadFile(path) //nolint:gosec // path is the caller's own config
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	return &cfg, nil
}

// findConfig walks up from the working directory, stopping at the
// filesystem root. Returns "" when there is none.
func findConfig() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	for {
		candidate := filepath.Join(dir, configName)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}

		dir = parent
	}
}

// openOutput returns the destination and a closer. "-" means stdout,
// which is not closed.
//
// A file is created 0600 and truncated. The mode is not incidental: the
// contents are a live bearer token, and the default 0644 would leave it
// readable by every account on a shared machine for the whole of its
// lifetime.
func openOutput(path string) (io.Writer, func(), error) {
	if path == "" || path == "-" {
		return os.Stdout, func() {}, nil
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", path, err)
	}

	// Re-assert the mode: O_CREATE only applies it when the file did not
	// already exist, so an existing world-readable file would otherwise
	// keep its permissions and quietly receive a token.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()

		return nil, nil, fmt.Errorf("chmod %s: %w", path, err)
	}

	return f, func() { _ = f.Close() }, nil
}
