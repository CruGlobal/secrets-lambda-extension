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
	"reflect"
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
	// The exec tests run this test binary as the command, to see what it was given.
	if os.Getenv(helperVariable) == "1" {
		json.NewEncoder(os.Stdout).Encode(helperOutput{Pid: os.Getpid(), Args: os.Args, Environ: os.Environ()})
		os.Exit(0)
	}
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

// setDeny makes every later call fail with AccessDeniedException. It takes the lock because
// the server's handler goroutines read deny.
func (s *ssmServer) setDeny(deny bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deny = deny
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

const helperVariable = "SECRETS_TEST_PRINT_ENVIRONMENT"

// helperOutput is what the test binary prints when it runs as the command.
type helperOutput struct {
	Pid     int
	Args    []string
	Environ []string
}

type result struct {
	stdout, stderr string
	code           int
	pid            int
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
	return result{stdout.String(), stderr.String(), code, cmd.Process.Pid}
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
			server.setDeny(tc.deny)
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

// TestWrapperModeFailsWhenTheFileCanNotBeWritten runs the binary with a file size limit of
// zero, so every write to the exports file fails, as it would with /tmp full.
func TestWrapperModeFailsWhenTheFileCanNotBeWritten(t *testing.T) {
	server := newSSMServer(t, fixture())
	env := testEnvironment(t, server)
	binary := secretsBinary(t)
	cacheFile := filepath.Join(lookup(env, "TMPDIR"), "org.cru.secrets-lambda-cache", "example-app-production-0")

	got := run(t, env, "/bin/sh", "-c", `ulimit -f 0 && exec "$0" "$@"`, binary)
	if got.code != 1 {
		t.Fatalf("exit %d, stdout %q, stderr %q; want exit 1", got.code, got.stdout, got.stderr)
	}
	if !strings.HasPrefix(got.stdout, "Error writing cache file: ") {
		t.Errorf("stdout = %q", got.stdout)
	}
	if _, err := os.Stat(cacheFile); !os.IsNotExist(err) {
		t.Errorf("a failed write left the cache file behind (stat: %v)", err)
	}

	// With room to write, the next start loads again instead of trusting a short file.
	again := run(t, env, binary)
	if again.code != 0 || again.stdout != cacheFile {
		t.Fatalf("exit %d, stdout %q, stderr %q", again.code, again.stdout, again.stderr)
	}
	if server.callCount("GetParametersByPath") != 2 {
		t.Errorf("GetParametersByPath calls = %d, want 2", server.callCount("GetParametersByPath"))
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

// TestWrapperFailsWhenItCanNotReadTheFile gives the wrapper a secrets stand-in that exits 0
// but prints a path it can't source. The wrapper must exit 1 and never run the command.
func TestWrapperFailsWhenItCanNotReadTheFile(t *testing.T) {
	dir := t.TempDir()
	unreadable := filepath.Join(dir, "unreadable")
	if err := os.WriteFile(unreadable, []byte("export API_KEY=abc123\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"missing":   filepath.Join(dir, "missing"),
		"directory": dir,
		"empty":     "",
	}
	if os.Geteuid() != 0 { // root reads it anyway
		cases["unreadable"] = unreadable
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			stub := filepath.Join(t.TempDir(), "secrets")
			body := fmt.Sprintf("#!/bin/sh\nprintf '%%s' '%s'\n", path)
			if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(t.TempDir(), "command-ran")
			got := run(t, []string{"PATH=" + os.Getenv("PATH")}, wrapperScript(t, stub), "touch", marker)
			if got.code != 1 {
				t.Errorf("exit %d, stdout %q, stderr %q; want exit 1", got.code, got.stdout, got.stderr)
			}
			if want := "Failed to retrieve secrets: could not read " + path + "\n"; got.stdout != want {
				t.Errorf("stdout = %q, want %q", got.stdout, want)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Error("the wrapper ran the command without its secrets")
			}
		})
	}
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

// helper returns the path of this test binary, which prints what it was given when
// helperVariable is set.
func helper(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(path, " \t\n") {
		t.Skipf("the wrapper splits its arguments on spaces, and the test binary's path has one: %q", path)
	}
	return path
}

func parseHelper(t *testing.T, got result) (helperOutput, map[string]string) {
	t.Helper()
	if got.code != 0 {
		t.Fatalf("exit %d, stdout %q, stderr %q", got.code, got.stdout, got.stderr)
	}
	var output helperOutput
	if err := json.Unmarshal([]byte(got.stdout), &output); err != nil {
		t.Fatalf("the command's output isn't the helper's: %v\n%s", err, got.stdout)
	}
	environ := map[string]string{}
	for _, entry := range output.Environ {
		if name, value, ok := strings.Cut(entry, "="); ok {
			if _, seen := environ[name]; seen {
				t.Errorf("%s is in the environment more than once", name)
			}
			environ[name] = value
		}
	}
	return output, environ
}

// TestExecModeEndToEnd runs `secrets exec` for real: the binary loads from the fake and
// execs this test binary, which reports what it was given.
func TestExecModeEndToEnd(t *testing.T) {
	server := newSSMServer(t, fixture())
	env := testEnvironment(t, server, helperVariable+"=1", "API_KEY=set-before-the-load", "UNRELATED=kept")
	command := helper(t)
	args := []string{"api", "two words", "--", "it's \"quoted\"", "$HOME", "line\nbreak", ""}

	got := run(t, env, secretsBinary(t), append([]string{"exec", "--", command}, args...)...)
	output, environ := parseHelper(t, got)

	if output.Pid != got.pid {
		t.Errorf("the command ran as pid %d, want %d: exec should replace the process", output.Pid, got.pid)
	}
	if want := append([]string{command}, args...); !reflect.DeepEqual(output.Args, want) {
		t.Errorf("args = %q, want %q", output.Args, want)
	}
	for _, name := range fixtureVariables {
		if want := fixture()["/ecs/example-app/prod/"+name]; environ[name] != want {
			t.Errorf("%s = %q, want %q", name, environ[name], want)
		}
	}
	if environ["UNRELATED"] != "kept" || environ["PROJECT_NAME"] != "example-app" {
		t.Errorf("UNRELATED = %q, PROJECT_NAME = %q", environ["UNRELATED"], environ["PROJECT_NAME"])
	}
	if _, ok := environ["github-token"]; ok {
		t.Error("github-token should have been skipped")
	}
	if got.stderr != "Skipping github-token: not a valid shell identifier\n" {
		t.Errorf("stderr = %q", got.stderr)
	}
	if entries, err := os.ReadDir(lookup(env, "TMPDIR")); err != nil || len(entries) != 0 {
		t.Errorf("exec mode wrote %d entries to TMPDIR (err %v), want none", len(entries), err)
	}
}

// TestExecModeMatchesTheWrapper starts the same command both ways and checks that it gets
// the same variables.
func TestExecModeMatchesTheWrapper(t *testing.T) {
	for _, mode := range []struct{ name, secretsParameters string }{
		{"by path", ""},
		{"named", "SECRETS_PARAMETERS=QUOTED,MULTI_LINE,API_KEY"},
	} {
		t.Run(mode.name, func(t *testing.T) {
			server := newSSMServer(t, fixture())
			env := testEnvironment(t, server, helperVariable+"=1", "API_KEY=set-before-the-load")
			if mode.secretsParameters != "" {
				env = append(env, mode.secretsParameters)
			}
			command := helper(t)
			_, viaWrapper := parseHelper(t, run(t, env, wrapperScript(t, secretsBinary(t)), command))
			_, viaExec := parseHelper(t, run(t, env, secretsBinary(t), "exec", command))

			for _, name := range fixtureVariables {
				if viaExec[name] != viaWrapper[name] {
					t.Errorf("%s: exec gave %q, the wrapper gave %q", name, viaExec[name], viaWrapper[name])
				}
			}
			if viaExec["API_KEY"] != "abc123" {
				t.Errorf("API_KEY = %q, want the SSM value", viaExec["API_KEY"])
			}
		})
	}
}

func TestExecModeLoadsEveryPage(t *testing.T) {
	parameters := map[string]string{}
	for i := 1; i <= 25; i++ {
		parameters[fmt.Sprintf("/ecs/example-app/prod/PARAM_%02d", i)] = fmt.Sprintf("value-%d", i)
	}
	server := newSSMServer(t, parameters)
	env := testEnvironment(t, server, helperVariable+"=1")

	_, environ := parseHelper(t, run(t, env, secretsBinary(t), "exec", "--", helper(t)))
	for name, value := range parameters {
		if key := strings.TrimPrefix(name, "/ecs/example-app/prod/"); environ[key] != value {
			t.Errorf("%s = %q, want %q", key, environ[key], value)
		}
	}
	if calls := server.callCount("GetParametersByPath"); calls != 3 {
		t.Errorf("GetParametersByPath calls = %d, want 3 pages of up to 10", calls)
	}
}

// TestExecModeFailsClosed checks that every failure exits 1 with a message on stderr and
// never starts the command.
func TestExecModeFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		env     func([]string) []string
		deny    bool
		args    func(command string) []string
		message string
	}{
		{"access denied", nil, true, nil, "Failed to retrieve secrets: Error fetching parameters: "},
		{"missing named parameter", func(e []string) []string { return append(e, "SECRETS_PARAMETERS=API_KEY,MISSING") }, false, nil,
			"Failed to retrieve secrets: Error fetching parameters: not found under /ecs/example-app/prod/: MISSING\n"},
		{"invalid name", func(e []string) []string { return append(e, "SECRETS_PARAMETERS=github-token") }, false, nil,
			"Failed to retrieve secrets: Invalid SECRETS_PARAMETERS: not valid environment variable names: \"github-token\"\n"},
		{"no project", func(e []string) []string { return without(e, "PROJECT_NAME") }, false, nil,
			"Failed to retrieve secrets: PROJECT_NAME environment variable not set\n"},
		{"no command", nil, false, func(string) []string { return []string{"exec", "--"} },
			"secrets exec: no command given. Usage: secrets exec [--] <command> [args...]\n"},
		{"command missing", nil, false, func(string) []string { return []string{"exec", "--", "/no/such/command"} },
			"secrets exec: cannot run /no/such/command: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newSSMServer(t, fixture())
			server.setDeny(tc.deny)
			env := testEnvironment(t, server, helperVariable+"=1")
			if tc.env != nil {
				env = tc.env(env)
			}
			command := helper(t)
			args := []string{"exec", "--", command}
			if tc.args != nil {
				args = tc.args(command)
			}

			got := run(t, env, secretsBinary(t), args...)
			if got.code != 1 {
				t.Errorf("exit %d, want 1", got.code)
			}
			if got.stdout != "" {
				t.Errorf("the command ran: stdout %q", got.stdout)
			}
			// The command is looked up after the load, so a by-path load's skip note can come first.
			if !strings.Contains(got.stderr, tc.message) {
				t.Errorf("stderr = %q, want it to hold %q", got.stderr, tc.message)
			}
			if strings.Contains(got.stderr, "abc123") {
				t.Errorf("stderr leaks a parameter value: %q", got.stderr)
			}
			if tc.deny && server.callCount("GetParametersByPath") != 1 {
				t.Errorf("the denied call never reached the fake: %v", server.calls)
			}
		})
	}
}
