package profile

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// fakeSSM returns canned pages, recording what it was asked for.
type fakeSSM struct {
	pages []*ssm.GetParametersByPathOutput
	err   error

	calls          int
	lastInput      *ssm.GetParametersByPathInput
	sawDecryption  bool
	sawNextTokenIn []string
}

func (f *fakeSSM) GetParametersByPath(
	_ context.Context,
	in *ssm.GetParametersByPathInput,
	_ ...func(*ssm.Options),
) (*ssm.GetParametersByPathOutput, error) {
	f.calls++
	f.lastInput = in

	if in.WithDecryption != nil && *in.WithDecryption {
		f.sawDecryption = true
	}

	if in.NextToken != nil {
		f.sawNextTokenIn = append(f.sawNextTokenIn, *in.NextToken)
	}

	if f.err != nil {
		return nil, f.err
	}

	page := f.pages[0]
	f.pages = f.pages[1:]

	return page, nil
}

func param(name, value string) ssmtypes.Parameter {
	return ssmtypes.Parameter{Name: aws.String(name), Value: aws.String(value)}
}

// Consumers key the profile by leaf name (client_id), not by the full
// path, so a tree can move without every consumer changing.
func TestReadKeysByLeafName(t *testing.T) {
	f := &fakeSSM{pages: []*ssm.GetParametersByPathOutput{{
		Parameters: []ssmtypes.Parameter{
			param("/dms/e2e/devel/client_id", "cid"),
			param("/dms/e2e/devel/api_url", "https://dms.devel.example.xyz"),
		},
	}}}

	got, err := Read(context.Background(), f, "/dms/e2e/devel")
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if got["client_id"] != "cid" || got["api_url"] != "https://dms.devel.example.xyz" {
		t.Errorf("got %v", got)
	}
}

// A tree that grows past one page must not silently return a partial
// profile — that would surface as a missing key, not as a paging bug.
func TestReadFollowsPagination(t *testing.T) {
	f := &fakeSSM{pages: []*ssm.GetParametersByPathOutput{
		{Parameters: []ssmtypes.Parameter{param("/p/a", "1")}, NextToken: aws.String("more")},
		{Parameters: []ssmtypes.Parameter{param("/p/b", "2")}},
	}}

	got, err := Read(context.Background(), f, "/p")
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if f.calls != 2 {
		t.Errorf("made %d calls, want 2", f.calls)
	}

	if len(f.sawNextTokenIn) != 1 || f.sawNextTokenIn[0] != "more" {
		t.Errorf("continuation token not passed back: %v", f.sawNextTokenIn)
	}

	if got["a"] != "1" || got["b"] != "2" {
		t.Errorf("paginated result incomplete: %v", got)
	}
}

// Without decryption a SecureString comes back as ciphertext and fails
// later at the token endpoint as invalid_client, which reads as a wrong
// credential rather than a missing kms:Decrypt grant.
func TestReadAlwaysRequestsDecryption(t *testing.T) {
	f := &fakeSSM{pages: []*ssm.GetParametersByPathOutput{{
		Parameters: []ssmtypes.Parameter{param("/p/a", "1")},
	}}}

	if _, err := Read(context.Background(), f, "/p"); err != nil {
		t.Fatalf("read: %v", err)
	}

	if !f.sawDecryption {
		t.Error("WithDecryption was not requested")
	}

	if f.lastInput.Recursive == nil || !*f.lastInput.Recursive {
		t.Error("Recursive was not requested")
	}
}

// An empty tree is the first-run state and must say so, rather than
// returning an empty map that fails much later as a missing key.
func TestReadRefusesAnEmptyTree(t *testing.T) {
	f := &fakeSSM{pages: []*ssm.GetParametersByPathOutput{{}}}

	_, err := Read(context.Background(), f, "/nope")
	if err == nil {
		t.Fatal("want an error for an empty tree, got nil")
	}

	if !strings.Contains(err.Error(), "/nope") {
		t.Errorf("error %q does not name the path", err)
	}
}

// AccessDenied means the resolved identity lacks a grant. Losing that
// text would turn a one-line IAM fix into a debugging session.
func TestReadSurfacesTheAWSError(t *testing.T) {
	f := &fakeSSM{err: errors.New("AccessDeniedException: not authorized to perform ssm:GetParametersByPath")}

	_, err := Read(context.Background(), f, "/p")
	if err == nil {
		t.Fatal("want an error, got nil")
	}

	if !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Errorf("error %q loses the AWS error", err)
	}
}

// The output of this tool goes straight into CI logs. A client secret
// surviving into it costs a rotation, so this is the assertion that
// matters most in the package.
func TestPublicDropsCredentials(t *testing.T) {
	p := Profile{
		"client_id":       "public-id",
		"client_secret":   "SUPER-SECRET",
		"api_url":         "https://dms.devel.example.xyz",
		"pool_id":         "eu-central-1_abc",
		"admin_password":  "hunter2",
		"private_key_pem": "-----BEGIN",
	}

	out := p.Public()

	for _, banned := range []string{"client_secret", "admin_password", "private_key_pem"} {
		if _, ok := out[banned]; ok {
			t.Errorf("%s survived into the public profile", banned)
		}
	}

	// Not merely absent by key — the VALUE must not appear anywhere.
	for _, secret := range []string{"SUPER-SECRET", "hunter2", "-----BEGIN"} {
		for k, v := range out {
			if strings.Contains(v, secret) {
				t.Errorf("secret value leaked through key %q: %q", k, v)
			}
		}
	}

	for _, want := range []string{"client_id", "api_url", "pool_id"} {
		if out[want] == "" {
			t.Errorf("%s should have been passed through", want)
		}
	}
}

// An incomplete tree is the likely first-run failure. It should name
// what is missing rather than surfacing as invalid_client from Cognito.
func TestValidateNamesMissingKeys(t *testing.T) {
	err := Profile{"client_id": "id"}.Validate()
	if err == nil {
		t.Fatal("want an error for an incomplete profile, got nil")
	}

	for _, want := range []string{"client_secret", "token_url", "scopes"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name the missing %s", err, want)
		}
	}
}

func TestValidateAcceptsACompleteProfile(t *testing.T) {
	p := Profile{"client_id": "i", "client_secret": "s", "token_url": "u", "scopes": "a/b"}
	if err := p.Validate(); err != nil {
		t.Errorf("complete profile rejected: %v", err)
	}
}

// Both forms are natural to type into an SSM parameter; choosing one
// silently would just be a trap for whoever typed the other.
func TestScopesAcceptSpaceAndComma(t *testing.T) {
	for _, raw := range []string{"a/read b/write", "a/read,b/write", " a/read , b/write "} {
		got := Profile{"scopes": raw}.Scopes()
		if len(got) != 2 || got[0] != "a/read" || got[1] != "b/write" {
			t.Errorf("Scopes(%q) = %v", raw, got)
		}
	}
}
