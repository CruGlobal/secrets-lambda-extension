package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go"
)

const testPrefix = "/ecs/example-app/prod/"

// fakeSSM serves parameters from a map of full name to value and records every call.
type fakeSSM struct {
	parameters    map[string]string
	getErr        error
	byPathCalls   int
	getCalls      [][]string
	getDecryption []bool
}

func (f *fakeSSM) GetParametersByPath(_ context.Context, input *ssm.GetParametersByPathInput, _ ...func(*ssm.Options)) (*ssm.GetParametersByPathOutput, error) {
	f.byPathCalls++
	output := &ssm.GetParametersByPathOutput{}
	for name, value := range f.parameters {
		if strings.HasPrefix(name, aws.ToString(input.Path)) {
			output.Parameters = append(output.Parameters, types.Parameter{Name: aws.String(name), Value: aws.String(value)})
		}
	}
	return output, nil
}

func (f *fakeSSM) GetParameters(_ context.Context, input *ssm.GetParametersInput, _ ...func(*ssm.Options)) (*ssm.GetParametersOutput, error) {
	f.getCalls = append(f.getCalls, append([]string(nil), input.Names...))
	f.getDecryption = append(f.getDecryption, aws.ToBool(input.WithDecryption))
	if f.getErr != nil {
		return nil, f.getErr
	}
	if len(input.Names) > 10 {
		return nil, fmt.Errorf("fake: %d names is more than GetParameters allows", len(input.Names))
	}
	output := &ssm.GetParametersOutput{}
	for _, name := range input.Names {
		if value, ok := f.parameters[name]; ok {
			output.Parameters = append(output.Parameters, types.Parameter{Name: aws.String(name), Value: aws.String(value)})
		} else {
			output.InvalidParameters = append(output.InvalidParameters, name)
		}
	}
	return output, nil
}

// seeded returns a fake holding PARAM_1..PARAM_n under testPrefix, each valued secret-value-<i>.
func seeded(n int) (*fakeSSM, []string) {
	f := &fakeSSM{parameters: map[string]string{}}
	names := make([]string, n)
	for i := range names {
		names[i] = fmt.Sprintf("PARAM_%d", i+1)
		f.parameters[testPrefix+names[i]] = fmt.Sprintf("secret-value-%d", i+1)
	}
	return f, names
}

func TestShellIdentifier(t *testing.T) {
	exportable := []string{"DATABASE_URL", "_private", "A1"}
	for _, key := range exportable {
		if !shellIdentifier.MatchString(key) {
			t.Errorf("%q should be exportable", key)
		}
	}

	skipped := []string{"github-token", "1A", "", "a b"}
	for _, key := range skipped {
		if shellIdentifier.MatchString(key) {
			t.Errorf("%q should be skipped", key)
		}
	}
}

func TestParseParameterNames(t *testing.T) {
	cases := map[string][]string{
		"DATABASE_URL":                      {"DATABASE_URL"},
		" DATABASE_URL , API_KEY ":          {"DATABASE_URL", "API_KEY"},
		"API_KEY,API_KEY, API_KEY":          {"API_KEY"},
		",DATABASE_URL,,API_KEY,":           {"DATABASE_URL", "API_KEY"},
		"B_SECOND,A_FIRST":                  {"B_SECOND", "A_FIRST"},
		"none":                              {},
		" none\n":                           {},
		"":                                  {},
		"   ":                               {},
		",, ,":                              {},
		"NONE":                              {"NONE"},
		"_private,A1,DATABASE_URL,_private": {"_private", "A1", "DATABASE_URL"},
	}
	for value, want := range cases {
		got, err := parseParameterNames(value)
		if err != nil {
			t.Errorf("parseParameterNames(%q) failed: %v", value, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parseParameterNames(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestParseParameterNamesRefusesInvalidNames(t *testing.T) {
	cases := map[string][]string{
		"DATABASE_URL,github-token":  {"github-token"},
		"1A":                         {"1A"},
		"a b,API_KEY":                {"a b"},
		"/ecs/example-app/prod/FOO":  {"/ecs/example-app/prod/FOO"},
		"FOO:1":                      {"FOO:1"},
		"none,bad.name,also-bad,BAR": {"bad.name", "also-bad"},
	}
	for value, bad := range cases {
		names, err := parseParameterNames(value)
		if err == nil {
			t.Errorf("parseParameterNames(%q) = %q, want an error", value, names)
			continue
		}
		for _, name := range bad {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("parseParameterNames(%q) error %q should name %q", value, err, name)
			}
		}
	}
}

func TestNamedParametersFromEnvironment(t *testing.T) {
	t.Run("unset is by-path mode", func(t *testing.T) {
		// t.Setenv registers a restore; Unsetenv then makes the variable truly absent.
		t.Setenv("SECRETS_PARAMETERS", "")
		if err := os.Unsetenv("SECRETS_PARAMETERS"); err != nil {
			t.Fatal(err)
		}
		names, named, err := namedParameters()
		if err != nil || named || names != nil {
			t.Errorf("namedParameters() = %q, %v, %v; want nil, false, nil", names, named, err)
		}
	})
	for _, value := range []string{"", "none", " , "} {
		t.Run(fmt.Sprintf("%q is named mode with nothing to load", value), func(t *testing.T) {
			t.Setenv("SECRETS_PARAMETERS", value)
			names, named, err := namedParameters()
			if err != nil || !named || len(names) != 0 {
				t.Errorf("namedParameters() = %q, %v, %v; want [], true, nil", names, named, err)
			}
		})
	}
	t.Run("a list is named mode", func(t *testing.T) {
		t.Setenv("SECRETS_PARAMETERS", "API_KEY, DATABASE_URL")
		names, named, err := namedParameters()
		if err != nil || !named || !reflect.DeepEqual(names, []string{"API_KEY", "DATABASE_URL"}) {
			t.Errorf("namedParameters() = %q, %v, %v", names, named, err)
		}
	})
	t.Run("an invalid name is an error", func(t *testing.T) {
		t.Setenv("SECRETS_PARAMETERS", "API_KEY,github-token")
		if _, _, err := namedParameters(); err == nil {
			t.Error("namedParameters() should refuse github-token")
		}
	})
}

func TestFetchByNameBatches(t *testing.T) {
	for _, tc := range []struct {
		count   int
		batches []int
	}{
		{1, []int{1}},
		{10, []int{10}},
		{11, []int{10, 1}},
		{25, []int{10, 10, 5}},
	} {
		t.Run(fmt.Sprintf("%d names", tc.count), func(t *testing.T) {
			f, names := seeded(tc.count + 3) // extra parameters a by-path read would pick up
			names = names[:tc.count]

			parameters, err := fetch(context.Background(), f, testPrefix, names, true)
			if err != nil {
				t.Fatalf("fetch failed: %v", err)
			}
			if f.byPathCalls != 0 {
				t.Errorf("named mode read by path %d times", f.byPathCalls)
			}
			sizes := make([]int, len(f.getCalls))
			requested := make([]string, 0)
			for i, call := range f.getCalls {
				sizes[i] = len(call)
				requested = append(requested, call...)
				if !f.getDecryption[i] {
					t.Errorf("GetParameters call %d did not ask for decryption", i+1)
				}
			}
			if !reflect.DeepEqual(sizes, tc.batches) {
				t.Errorf("batch sizes = %v, want %v", sizes, tc.batches)
			}
			want := make([]string, len(names))
			for i, name := range names {
				want[i] = testPrefix + name
			}
			if !reflect.DeepEqual(requested, want) {
				t.Errorf("requested %q, want %q", requested, want)
			}
			if len(parameters) != tc.count {
				t.Errorf("got %d parameters, want %d", len(parameters), tc.count)
			}
		})
	}
}

func TestFetchByNameWithNothingToLoad(t *testing.T) {
	for _, value := range []string{"none", "", "  ", ","} {
		t.Run(fmt.Sprintf("%q", value), func(t *testing.T) {
			f, _ := seeded(3)
			names, err := parseParameterNames(value)
			if err != nil {
				t.Fatal(err)
			}
			parameters, err := fetch(context.Background(), f, testPrefix, names, true)
			if err != nil {
				t.Fatalf("fetch failed: %v", err)
			}
			if len(parameters) != 0 {
				t.Errorf("loaded %d parameters, want none", len(parameters))
			}
			if f.byPathCalls != 0 || len(f.getCalls) != 0 {
				t.Errorf("made %d by-path and %d GetParameters calls, want none", f.byPathCalls, len(f.getCalls))
			}
		})
	}
}

func TestFetchByNameRefusesMissingNames(t *testing.T) {
	f, names := seeded(12)
	// One missing name in each batch, so the error must collect across batches.
	requested := append([]string{"MISSING_ONE"}, names[:10]...)
	requested = append(requested, "MISSING_TWO")

	parameters, err := fetch(context.Background(), f, testPrefix, requested, true)
	if err == nil {
		t.Fatalf("fetch should fail, got %d parameters", len(parameters))
	}
	if parameters != nil {
		t.Errorf("a failed fetch returned %d parameters", len(parameters))
	}
	message := err.Error()
	for _, name := range []string{"MISSING_ONE", "MISSING_TWO"} {
		if !strings.Contains(message, name) {
			t.Errorf("error %q should name %s", message, name)
		}
	}
	if strings.Contains(message, "secret-value") {
		t.Errorf("error %q leaks a parameter value", message)
	}
	if strings.Contains(message, "PARAM_") {
		t.Errorf("error %q names parameters that were found", message)
	}
	if f.byPathCalls != 0 {
		t.Errorf("named mode read by path %d times", f.byPathCalls)
	}
}

func TestFetchByNameRefusesAShortResponse(t *testing.T) {
	// A response that drops a name without listing it in InvalidParameters still fails.
	f, names := seeded(2)
	short := &shortSSM{fakeSSM: f, drop: testPrefix + names[1]}
	if _, err := fetch(context.Background(), short, testPrefix, names, true); err == nil || !strings.Contains(err.Error(), names[1]) {
		t.Errorf("fetch error = %v, want one naming %s", err, names[1])
	}
}

type shortSSM struct {
	*fakeSSM
	drop string
}

func (s *shortSSM) GetParameters(ctx context.Context, input *ssm.GetParametersInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersOutput, error) {
	output, err := s.fakeSSM.GetParameters(ctx, input, optFns...)
	if err != nil {
		return nil, err
	}
	kept := output.Parameters[:0]
	for _, parameter := range output.Parameters {
		if aws.ToString(parameter.Name) != s.drop {
			kept = append(kept, parameter)
		}
	}
	output.Parameters = kept
	return output, nil
}

func TestFetchByNameRefusesAccessDenied(t *testing.T) {
	f, names := seeded(3)
	f.getErr = &smithy.GenericAPIError{
		Code:    "AccessDeniedException",
		Message: "not authorized to perform: ssm:GetParameters",
	}

	parameters, err := fetch(context.Background(), f, testPrefix, names, true)
	if err == nil {
		t.Fatalf("fetch should fail, got %d parameters", len(parameters))
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDeniedException" {
		t.Errorf("error %v should wrap the AccessDeniedException", err)
	}
	for _, name := range names {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q should name %s", err, name)
		}
	}
	if strings.Contains(err.Error(), "secret-value") {
		t.Errorf("error %q leaks a parameter value", err)
	}
	if f.byPathCalls != 0 {
		t.Errorf("named mode fell back to reading by path after AccessDenied")
	}
}

func TestFetchByPathWhenUnset(t *testing.T) {
	f, _ := seeded(3)
	f.parameters["/ecs/example-app/stage/OTHER_ENV"] = "not-this-one"

	parameters, err := fetch(context.Background(), f, testPrefix, nil, false)
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	if f.byPathCalls != 1 || len(f.getCalls) != 0 {
		t.Errorf("made %d by-path and %d GetParameters calls, want 1 and 0", f.byPathCalls, len(f.getCalls))
	}
	if len(parameters) != 3 {
		t.Errorf("loaded %d parameters, want 3", len(parameters))
	}
}

func TestBothModesWriteTheSameExports(t *testing.T) {
	f, names := seeded(3)
	f.parameters[testPrefix+"QUOTED"] = "it's got 'quotes' & $vars"
	names = append(names, "QUOTED")

	byPath, err := fetch(context.Background(), f, testPrefix, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	byName, err := fetch(context.Background(), f, testPrefix, names, true)
	if err != nil {
		t.Fatal(err)
	}

	// The fake's by-path order follows map iteration; compare the lines as sets.
	var pathOut, nameOut bytes.Buffer
	writeExports(&pathOut, testPrefix, byPath)
	writeExports(&nameOut, testPrefix, byName)
	pathLines := strings.Split(strings.TrimSpace(pathOut.String()), "\n")
	nameLines := strings.Split(strings.TrimSpace(nameOut.String()), "\n")
	if !sameSet(pathLines, nameLines) {
		t.Errorf("by-path wrote %q, by-name wrote %q", pathLines, nameLines)
	}
	if !strings.Contains(nameOut.String(), "export PARAM_1=secret-value-1\n") {
		t.Errorf("unexpected export format: %q", nameOut.String())
	}
	if !strings.Contains(nameOut.String(), `export QUOTED='it'"'"'s got '"'"'quotes'"'"' & $vars'`) {
		t.Errorf("value was not shell-quoted: %q", nameOut.String())
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[string]int{}
	for _, s := range a {
		counts[s]++
	}
	for _, s := range b {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}
