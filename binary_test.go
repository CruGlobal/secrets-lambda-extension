package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// The tests in this file build the real binary and run it against a fake SSM endpoint, so
// they see what callers see: the exit code, stdout, stderr and the exports file.

var (
	buildDir    string
	buildOnce   sync.Once
	builtBinary string
	buildErr    error
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "secrets-test-bin-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	buildDir = dir
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// secretsBinary builds the binary once per test run, the way the release does, and
// returns its path.
func secretsBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		builtBinary = filepath.Join(buildDir, "secrets")
		cmd := exec.Command("go", "build", "-o", builtBinary, ".")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build failed: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return builtBinary
}

// ssmServer is a fake SSM endpoint that speaks the JSON protocol the SDK uses. It serves
// parameters from a map of full name to value and counts the calls to each operation.
type ssmServer struct {
	*httptest.Server
	mu         sync.Mutex
	parameters map[string]string
	deny       bool
	calls      map[string]int
}

func newSSMServer(t *testing.T, parameters map[string]string) *ssmServer {
	t.Helper()
	s := &ssmServer{parameters: parameters, calls: map[string]int{}}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

func (s *ssmServer) callCount(operation string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[operation]
}

type ssmParameter struct {
	Name  string
	Type  string
	Value string
}

func (s *ssmServer) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonSSM.")
	s.calls[operation]++
	var input struct {
		Path       string
		Names      []string
		MaxResults int
		NextToken  string
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeSSMError(w, "ValidationException", err.Error())
		return
	}
	if s.deny {
		writeSSMError(w, "AccessDeniedException", "not authorized to perform: ssm:"+operation)
		return
	}
	switch operation {
	case "GetParametersByPath":
		// Not recursive: only names directly under the path, in name order, one page at a time.
		names := make([]string, 0)
		for name := range s.parameters {
			if rest, ok := strings.CutPrefix(name, input.Path); ok && !strings.Contains(rest, "/") {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		start, _ := strconv.Atoi(input.NextToken)
		end := len(names)
		if input.MaxResults > 0 && start+input.MaxResults < end {
			end = start + input.MaxResults
		}
		output := struct {
			Parameters []ssmParameter
			NextToken  string `json:",omitempty"`
		}{Parameters: make([]ssmParameter, 0)}
		for _, name := range names[start:end] {
			output.Parameters = append(output.Parameters, ssmParameter{name, "SecureString", s.parameters[name]})
		}
		if end < len(names) {
			output.NextToken = strconv.Itoa(end)
		}
		writeSSM(w, output)
	case "GetParameters":
		output := struct {
			Parameters        []ssmParameter
			InvalidParameters []string
		}{make([]ssmParameter, 0), make([]string, 0)}
		for _, name := range input.Names {
			if value, ok := s.parameters[name]; ok {
				output.Parameters = append(output.Parameters, ssmParameter{name, "SecureString", value})
			} else {
				output.InvalidParameters = append(output.InvalidParameters, name)
			}
		}
		writeSSM(w, output)
	default:
		writeSSMError(w, "InvalidAction", "the fake does not serve "+operation)
	}
}

func writeSSM(w http.ResponseWriter, output any) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	json.NewEncoder(w).Encode(output)
}

func writeSSMError(w http.ResponseWriter, code, message string) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	w.Header().Set("X-Amzn-ErrorType", code)
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"__type": code, "message": message})
}

// fixture is a set of parameters whose values need every kind of care: shell quoting,
// several lines, and a name that isn't a valid identifier.
func fixture() map[string]string {
	return map[string]string{
		"/ecs/example-app/prod/API_KEY":      "abc123",
		"/ecs/example-app/prod/DATABASE_URL": "postgres://user:p@ss word@db.example.com:5432/app?sslmode=require",
		"/ecs/example-app/prod/MULTI_LINE":   "-----BEGIN PRIVATE KEY-----\nMIIB\nabc==\n-----END PRIVATE KEY-----\n",
		"/ecs/example-app/prod/QUOTED":       `it's got 'quotes', "double quotes", $vars, ` + "`backticks`" + ` and \backslashes`,
		"/ecs/example-app/prod/github-token": "skipped-value",
		"/ecs/example-app/prod/nested/CHILD": "not-recursive",
		"/ecs/example-app/stage/API_KEY":     "other-environment",
	}
}

// fixtureVariables are the variables the fixture should produce, in by-path order.
var fixtureVariables = []string{"API_KEY", "DATABASE_URL", "MULTI_LINE", "QUOTED"}

// testEnvironment is a clean environment that points the SDK at the fake and keeps it away
// from any real AWS configuration or credentials on the machine.
func testEnvironment(t *testing.T, server *ssmServer, extra ...string) []string {
	t.Helper()
	home := t.TempDir()
	return append([]string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"TMPDIR=" + t.TempDir(),
		"AWS_ENDPOINT_URL=" + server.URL,
		"AWS_ACCESS_KEY_ID=test-access-key",
		"AWS_SECRET_ACCESS_KEY=test-secret-key",
		"AWS_CONFIG_FILE=" + filepath.Join(home, "no-config"),
		"AWS_SHARED_CREDENTIALS_FILE=" + filepath.Join(home, "no-credentials"),
		"AWS_EC2_METADATA_DISABLED=true",
		"AWS_MAX_ATTEMPTS=1",
		"PROJECT_NAME=example-app",
		"ENVIRONMENT=production",
	}, extra...)
}

// without returns env with every entry for name removed.
func without(env []string, name string) []string {
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		if !strings.HasPrefix(entry, name+"=") {
			kept = append(kept, entry)
		}
	}
	return kept
}

func lookup(env []string, name string) string {
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, name+"="); ok {
			return value
		}
	}
	return ""
}

type result struct {
	stdout, stderr string
	code           int
}

func run(t *testing.T, env []string, name string, args ...string) result {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("could not run %s: %v", name, err)
	}
	return result{stdout.String(), stderr.String(), code}
}

// TestWrapperModeOutput pins what the binary does with no arguments, which is what
// secrets-wrapper relies on: the file's path on stdout with no newline, and the file's
// exact contents.
func TestWrapperModeOutput(t *testing.T) {
	binary := secretsBinary(t)
	server := newSSMServer(t, fixture())
	env := testEnvironment(t, server)
	cacheFile := filepath.Join(lookup(env, "TMPDIR"), "org.cru.secrets-lambda-cache", "example-app-production-0")

	got := run(t, env, binary)
	if got.code != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
	}
	if got.stdout != cacheFile {
		t.Errorf("stdout = %q, want the cache file's path %q with no newline", got.stdout, cacheFile)
	}
	if got.stderr != "Skipping github-token: not a valid shell identifier\n" {
		t.Errorf("stderr = %q", got.stderr)
	}
	contents, err := os.ReadFile(cacheFile)
	if err != nil {
		t.Fatal(err)
	}
	want := "export API_KEY=abc123\n" +
		"export DATABASE_URL='postgres://user:p@ss word@db.example.com:5432/app?sslmode=require'\n" +
		"export MULTI_LINE='-----BEGIN PRIVATE KEY-----\nMIIB\nabc==\n-----END PRIVATE KEY-----\n'\n" +
		`export QUOTED='it'"'"'s got '"'"'quotes'"'"', "double quotes", $vars, ` + "`backticks`" + ` and \backslashes'` + "\n"
	if string(contents) != want {
		t.Errorf("exports file =\n%s\nwant\n%s", contents, want)
	}
	if server.callCount("GetParametersByPath") != 1 || server.callCount("GetParameters") != 0 {
		t.Errorf("calls = %v, want one GetParametersByPath", server.calls)
	}

	// A second start in the same environment reads the file, not SSM.
	again := run(t, env, binary)
	if again.code != 0 || again.stdout != cacheFile {
		t.Errorf("second run: exit %d, stdout %q", again.code, again.stdout)
	}
	if server.callCount("GetParametersByPath") != 1 {
		t.Errorf("second run called SSM again: %v", server.calls)
	}
}

func TestWrapperModeNamesTheFileByBuildNumber(t *testing.T) {
	server := newSSMServer(t, fixture())
	env := testEnvironment(t, server, "BUILD_NUMBER=42", "ENVIRONMENT=staging")
	got := run(t, env, secretsBinary(t))
	want := filepath.Join(lookup(env, "TMPDIR"), "org.cru.secrets-lambda-cache", "example-app-staging-42")
	if got.code != 0 || got.stdout != want {
		t.Errorf("exit %d, stdout %q, want %q", got.code, got.stdout, want)
	}
}

func TestWrapperModeNamedParameters(t *testing.T) {
	server := newSSMServer(t, fixture())
	env := testEnvironment(t, server, "SECRETS_PARAMETERS=QUOTED, API_KEY")
	got := run(t, env, secretsBinary(t))
	if got.code != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
	}
	contents, err := os.ReadFile(got.stdout)
	if err != nil {
		t.Fatal(err)
	}
	want := `export QUOTED='it'"'"'s got '"'"'quotes'"'"', "double quotes", $vars, ` + "`backticks`" + ` and \backslashes'` + "\n" +
		"export API_KEY=abc123\n"
	if string(contents) != want {
		t.Errorf("exports file = %q, want %q", contents, want)
	}
	if server.callCount("GetParametersByPath") != 0 || server.callCount("GetParameters") != 1 {
		t.Errorf("calls = %v, want one GetParameters", server.calls)
	}
}

// TestWrapperModeFailures pins the failure output: exit 1 and one line on stdout, which the
// wrapper logs after "Failed to retrieve secrets: ".
func TestWrapperModeFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		env    func([]string) []string
		deny   bool
		stdout string
	}{
		{"no project", func(e []string) []string { return without(e, "PROJECT_NAME") }, false, "PROJECT_NAME environment variable not set\n"},
		{"no environment", func(e []string) []string { return without(e, "ENVIRONMENT") }, false, "ENVIRONMENT environment variable not set\n"},
		{"bad name", func(e []string) []string { return append(e, "SECRETS_PARAMETERS=API_KEY,github-token") }, false, "Invalid SECRETS_PARAMETERS: not valid environment variable names: \"github-token\"\n"},
		{"access denied", func(e []string) []string { return e }, true, "Error fetching parameters: "},
		{"missing named parameter", func(e []string) []string { return append(e, "SECRETS_PARAMETERS=API_KEY,MISSING") }, false, "Error fetching parameters: not found under /ecs/example-app/prod/: MISSING\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newSSMServer(t, fixture())
			server.deny = tc.deny
			env := tc.env(testEnvironment(t, server))
			got := run(t, env, secretsBinary(t))
			if got.code != 1 {
				t.Errorf("exit %d, want 1", got.code)
			}
			if !strings.HasPrefix(got.stdout, tc.stdout) || !strings.HasSuffix(got.stdout, "\n") {
				t.Errorf("stdout = %q, want it to start with %q", got.stdout, tc.stdout)
			}
			if strings.Contains(got.stdout+got.stderr, "abc123") {
				t.Errorf("output leaks a parameter value: %q %q", got.stdout, got.stderr)
			}
			if tc.deny && server.callCount("GetParametersByPath") != 1 {
				t.Errorf("the denied call never reached the fake: %v", server.calls)
			}
			cacheDir := filepath.Join(lookup(env, "TMPDIR"), "org.cru.secrets-lambda-cache")
			if entries, _ := os.ReadDir(cacheDir); len(entries) != 0 {
				t.Errorf("a failed load left %d files in the cache", len(entries))
			}
		})
	}
}

// wrapperScript copies scripts/secrets-wrapper into a temp folder, pointed at secrets
// instead of /opt/secrets-lambda-extension/bin/secrets.
func wrapperScript(t *testing.T, secrets string) string {
	t.Helper()
	source, err := os.ReadFile("scripts/secrets-wrapper")
	if err != nil {
		t.Fatal(err)
	}
	const installed = "/opt/secrets-lambda-extension/bin/secrets"
	if strings.Count(string(source), installed) != 1 {
		t.Fatalf("scripts/secrets-wrapper should call %s once", installed)
	}
	wrapper := filepath.Join(t.TempDir(), "secrets-wrapper")
	if err := os.WriteFile(wrapper, []byte(strings.Replace(string(source), installed, secrets, 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	return wrapper
}

// printVariables writes a bash script that prints each named variable as NAME=value and a
// NUL byte, so a value with newlines comes back whole.
func printVariables(t *testing.T) string {
	t.Helper()
	script := filepath.Join(t.TempDir(), "print-variables")
	body := "#!/bin/bash\nfor name in \"$@\"; do printf '%s=%s\\0' \"$name\" \"${!name}\"; done\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return script
}

func parseVariables(output string) map[string]string {
	variables := map[string]string{}
	for _, entry := range strings.Split(strings.TrimSuffix(output, "\x00"), "\x00") {
		if name, value, ok := strings.Cut(entry, "="); ok {
			variables[name] = value
		}
	}
	return variables
}

// TestWrapperRoundTrip runs the real wrapper: bash sources the exports file and runs a
// command, which must see every value exactly as SSM holds it.
func TestWrapperRoundTrip(t *testing.T) {
	server := newSSMServer(t, fixture())
	env := testEnvironment(t, server)
	wrapper := wrapperScript(t, secretsBinary(t))

	got := run(t, env, wrapper, append([]string{printVariables(t)}, fixtureVariables...)...)
	if got.code != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
	}
	variables := parseVariables(got.stdout)
	for _, name := range fixtureVariables {
		if want := fixture()["/ecs/example-app/prod/"+name]; variables[name] != want {
			t.Errorf("%s = %q, want %q", name, variables[name], want)
		}
	}
}
