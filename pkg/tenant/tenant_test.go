package tenant

import (
	"regexp"
	"testing"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestGenerateProducesOneIDPerName(t *testing.T) {
	got, err := Generate([]string{"primary", "secondary"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("got %d ids, want 2: %v", len(got), got)
	}

	for name, id := range got {
		if !uuidV4Re.MatchString(id) {
			t.Errorf("%s = %q, not a v4 UUID", name, id)
		}
	}
}

// The whole point of the pair is that the two tenants are different
// worlds. Identical ids would make every isolation test pass by
// accident.
func TestGenerateProducesDistinctIDs(t *testing.T) {
	got, err := Generate([]string{"primary", "secondary"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if got["primary"] == got["secondary"] {
		t.Error("both tenants got the same id")
	}
}

// Fresh ids per run give each run its own empty world; reusing them
// across runs would let one run's leftovers decide another run's result.
func TestGenerateIsFreshEachCall(t *testing.T) {
	first, err := Generate([]string{"primary"})
	if err != nil {
		t.Fatal(err)
	}

	second, err := Generate([]string{"primary"})
	if err != nil {
		t.Fatal(err)
	}

	if first["primary"] == second["primary"] {
		t.Error("two calls produced the same id — not random")
	}
}

// A repeated name almost certainly means a typo, and collapsing it
// silently would present as a test mysteriously sharing a tenant with
// itself.
func TestGenerateRefusesDuplicateNames(t *testing.T) {
	if _, err := Generate([]string{"primary", "primary"}); err == nil {
		t.Fatal("want an error for a duplicate name, got nil")
	}
}

func TestGenerateRefusesEmptyName(t *testing.T) {
	if _, err := Generate([]string{"primary", "  "}); err == nil {
		t.Fatal("want an error for an empty name, got nil")
	}
}

func TestGenerateOfNothingIsNothing(t *testing.T) {
	got, err := Generate(nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("got %v, want empty", got)
	}
}

func TestParseNames(t *testing.T) {
	cases := map[string][]string{
		"primary,secondary":    {"primary", "secondary"},
		" primary , secondary": {"primary", "secondary"},
		"primary,":             {"primary"},
		"":                     {},
	}

	for raw, want := range cases {
		got := ParseNames(raw)
		if len(got) != len(want) {
			t.Errorf("ParseNames(%q) = %v, want %v", raw, got, want)

			continue
		}

		for i := range want {
			if got[i] != want[i] {
				t.Errorf("ParseNames(%q) = %v, want %v", raw, got, want)

				break
			}
		}
	}
}
