// Package profile reads a Cognito client profile from an AWS Systems
// Manager parameter tree.
//
// The tree is where the coordinates live — pool id, app client id,
// client secret, token endpoint, scopes — rather than in each consuming
// repository's config. That placement is deliberate: a repository then
// commits only WHICH profile it wants, so rotating a client or moving a
// pool is an SSM write instead of a pull request in every repository
// that authenticates against it.
package profile

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// Required names the keys an exchange cannot proceed without.
var Required = []string{"client_id", "client_secret", "token_url", "scopes"}

// SSMAPI is the slice of the SSM client this package uses, so callers
// can substitute a fake without a live account.
type SSMAPI interface {
	GetParametersByPath(
		ctx context.Context,
		in *ssm.GetParametersByPathInput,
		optFns ...func(*ssm.Options),
	) (*ssm.GetParametersByPathOutput, error)
}

// Profile is a parameter tree flattened to its leaf names, so
// `/dms/e2e/devel/client_id` is reachable as `client_id` and the tree
// can move without every consumer changing.
type Profile map[string]string

// Read returns every parameter under path, decrypted.
//
// Decryption is always requested. A caller that could read the tree but
// not decrypt it would otherwise receive ciphertext as if it were the
// secret and fail at the token endpoint with `invalid_client` — which
// reads as a wrong credential rather than a missing kms:Decrypt grant.
func Read(ctx context.Context, api SSMAPI, path string) (Profile, error) {
	out := Profile{}

	var next *string

	for {
		page, err := api.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{
			Path:           aws.String(path),
			Recursive:      aws.Bool(true),
			WithDecryption: aws.Bool(true),
			NextToken:      next,
		})
		if err != nil {
			// AccessDenied means the resolved identity lacks a grant;
			// anything else is usually the path or the account being
			// wrong. Both are worth reading verbatim.
			return nil, fmt.Errorf("ssm %s: %w", path, err)
		}

		for _, p := range page.Parameters {
			out[leafName(aws.ToString(p.Name))] = aws.ToString(p.Value)
		}

		if page.NextToken == nil || *page.NextToken == "" {
			break
		}

		next = page.NextToken
	}

	if len(out) == 0 {
		return nil, fmt.Errorf(
			"ssm: no parameters under %q — wrong path, wrong account, or the tree is not provisioned", path)
	}

	return out, nil
}

// Validate reports which required keys are absent.
//
// Naming them matters: an incomplete tree is the likely first-run state,
// and without this it surfaces from Cognito as `invalid_client`, which
// reads as a broken credential rather than an unprovisioned one.
func (p Profile) Validate() error {
	missing := []string{}

	for _, k := range Required {
		if p[k] == "" {
			missing = append(missing, k)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	sort.Strings(missing)

	return fmt.Errorf("profile is missing %s — the SSM tree is incomplete", strings.Join(missing, ", "))
}

// Scopes accepts either the space-separated form OAuth uses on the wire
// or a comma-separated list, because both are natural to type into an
// SSM parameter and picking one would just be a trap for whoever types
// the other.
func (p Profile) Scopes() []string {
	return strings.FieldsFunc(p["scopes"], func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
}

// Public is the passthrough half of the output: everything a consuming
// suite might need (api_url, pool_id, issuer) minus anything that looks
// like a credential.
//
// The filter is deliberately over-eager. This output goes straight into
// CI logs, and omitting a harmless key costs a config edit while
// including a secret one costs a rotation — so a key is dropped on
// suspicion rather than on proof.
func (p Profile) Public() map[string]string {
	out := map[string]string{}

	for k, v := range p {
		if looksSecret(k) {
			continue
		}

		out[k] = v
	}

	return out
}

func looksSecret(key string) bool {
	lower := strings.ToLower(key)

	for _, marker := range []string{"secret", "password", "passwd", "private", "credential"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}

	return false
}

// leafName reduces a full parameter name to its last segment.
func leafName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}

	return name
}
