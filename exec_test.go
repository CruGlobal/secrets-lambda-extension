package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aws/smithy-go"
)

// keepEnvironment puts this process's environment back as it was when the test ends, since
// exec mode sets variables in it.
func keepEnvironment(t *testing.T) {
	t.Helper()
	saved := os.Environ()
	t.Cleanup(func() {
		os.Clearenv()
		for _, entry := range saved {
			if name, value, ok := strings.Cut(entry, "="); ok {
				os.Setenv(name, value)
			}
		}
	})
}

// execSetup gives a test a clean app environment and a directory on PATH holding an
// executable called example-command.
func execSetup(t *testing.T) (commandPath string) {
	t.Helper()
	keepEnvironment(t)
	dir := t.TempDir()
	commandPath = filepath.Join(dir, "example-command")
	if err := os.WriteFile(commandPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Clearenv()
	os.Setenv("PATH", dir)
	os.Setenv("PROJECT_NAME", "example-app")
	os.Setenv("ENVIRONMENT", "production")
	return commandPath
}

// clientFor hands prepareExec the fake, and counts how often it asked for a client.
func clientFor(f ssmClient, calls *int) func(context.Context) (ssmClient, error) {
	return func(context.Context) (ssmClient, error) {
		*calls++
		return f, nil
	}
}

func TestCommandLine(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"--", "/var/task/bootstrap", "api"}, []string{"/var/task/bootstrap", "api"}},
		{[]string{"/var/task/bootstrap", "api"}, []string{"/var/task/bootstrap", "api"}},
		{[]string{"example-command"}, []string{"example-command"}},
		// Only a leading -- belongs to exec. Everything after the command is the command's.
		{[]string{"example-command", "--", "-x"}, []string{"example-command", "--", "-x"}},
		{[]string{"--", "example-command", "--flag"}, []string{"example-command", "--flag"}},
		{[]string{"--", "-dash-command"}, []string{"-dash-command"}},
		{[]string{"--", "--"}, []string{"--"}},
	} {
		got, err := commandLine(tc.args)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("commandLine(%q) = %q, %v; want %q", tc.args, got, err, tc.want)
		}
	}
	for _, args := range [][]string{nil, {}, {"--"}, {""}, {"--", ""}, {"-x", "example-command"}, {"--help"}} {
		if got, err := commandLine(args); err == nil || !strings.HasPrefix(err.Error(), "secrets exec: ") {
			t.Errorf("commandLine(%q) = %q, %v; want a secrets exec error", args, got, err)
		}
	}
}

func TestExecSetsTheParameters(t *testing.T) {
	command := execSetup(t)
	os.Setenv("PARAM_1", "set-before-the-load")
	os.Setenv("UNRELATED", "kept")
	f, _ := seeded(3)
	f.parameters[testPrefix+"github-token"] = "skipped-value"
	var clients int

	path, argv, err := prepareExec(context.Background(), []string{"--", "example-command", "api"}, clientFor(f, &clients))
	if err != nil {
		t.Fatalf("prepareExec failed: %v", err)
	}
	if path != command || !reflect.DeepEqual(argv, []string{"example-command", "api"}) {
		t.Errorf("prepareExec = %q, %q; want %q, [example-command api]", path, argv, command)
	}
	if f.byPathCalls != 1 || len(f.getCalls) != 0 {
		t.Errorf("made %d by-path and %d GetParameters calls, want 1 and 0", f.byPathCalls, len(f.getCalls))
	}
	want := map[string]string{
		"PARAM_1":      "secret-value-1", // SSM wins over what was already set
		"PARAM_2":      "secret-value-2",
		"PARAM_3":      "secret-value-3",
		"UNRELATED":    "kept",
		"PROJECT_NAME": "example-app",
		"ENVIRONMENT":  "production",
	}
	for name, value := range want {
		if got, ok := os.LookupEnv(name); !ok || got != value {
			t.Errorf("%s = %q (set: %v), want %q", name, got, ok, value)
		}
	}
	if _, ok := os.LookupEnv("github-token"); ok {
		t.Error("github-token is not a valid identifier and should have been skipped")
	}
	if count := strings.Count(strings.Join(os.Environ(), "\n"), "PARAM_1="); count != 1 {
		t.Errorf("PARAM_1 is in the environment %d times, want once", count)
	}
}

func TestExecNamedMode(t *testing.T) {
	execSetup(t)
	os.Setenv("SECRETS_PARAMETERS", "PARAM_2, PARAM_1")
	f, _ := seeded(3)
	var clients int

	if _, _, err := prepareExec(context.Background(), []string{"example-command"}, clientFor(f, &clients)); err != nil {
		t.Fatalf("prepareExec failed: %v", err)
	}
	if f.byPathCalls != 0 || !reflect.DeepEqual(f.getCalls, [][]string{{testPrefix + "PARAM_2", testPrefix + "PARAM_1"}}) {
		t.Errorf("by-path calls %d, GetParameters calls %q", f.byPathCalls, f.getCalls)
	}
	if os.Getenv("PARAM_1") != "secret-value-1" || os.Getenv("PARAM_2") != "secret-value-2" {
		t.Errorf("PARAM_1 = %q, PARAM_2 = %q", os.Getenv("PARAM_1"), os.Getenv("PARAM_2"))
	}
	if _, ok := os.LookupEnv("PARAM_3"); ok {
		t.Error("PARAM_3 was not named and should not be set")
	}
}

func TestExecWithNothingToLoad(t *testing.T) {
	for _, value := range []string{"none", ""} {
		t.Run(value, func(t *testing.T) {
			command := execSetup(t)
			os.Setenv("SECRETS_PARAMETERS", value)
			before := os.Environ()
			f, _ := seeded(3)
			var clients int

			path, _, err := prepareExec(context.Background(), []string{"example-command"}, clientFor(f, &clients))
			if err != nil || path != command {
				t.Fatalf("prepareExec = %q, %v", path, err)
			}
			if f.byPathCalls != 0 || len(f.getCalls) != 0 {
				t.Errorf("made %d by-path and %d GetParameters calls, want none", f.byPathCalls, len(f.getCalls))
			}
			if !reflect.DeepEqual(os.Environ(), before) {
				t.Errorf("the environment changed with nothing to load")
			}
		})
	}
}

// TestExecValuesRoundTrip checks that values reach the environment byte for byte. Nothing
// is quoted, so nothing has to be unquoted.
func TestExecValuesRoundTrip(t *testing.T) {
	execSetup(t)
	values := map[string]string{
		"PEM":         "-----BEGIN PRIVATE KEY-----\nMIIB\nabc==\n-----END PRIVATE KEY-----\n",
		"QUOTES":      `it's got 'single' and "double" quotes`,
		"SHELL_CHARS": "$HOME ${PATH} `id` $(id) \\ ; | & > < * ? ~ #",
		"EQUALS":      "a=b==c",
		"SPACES":      "  leading and trailing  ",
		"NEWLINES":    "\n\nline\r\n\n",
		"UNICODE":     "héllo wörld ✓ 日本",
		"LONE_QUOTE":  "'",
		"LONG":        strings.Repeat("0123456789abcdef", 4096),
	}
	f := &fakeSSM{parameters: map[string]string{}}
	for name, value := range values {
		f.parameters[testPrefix+name] = value
	}
	var clients int

	if _, _, err := prepareExec(context.Background(), []string{"example-command"}, clientFor(f, &clients)); err != nil {
		t.Fatalf("prepareExec failed: %v", err)
	}
	environ := strings.Join(os.Environ(), "\x00") + "\x00"
	for name, value := range values {
		if got := os.Getenv(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
		if !strings.Contains(environ, "\x00"+name+"="+value+"\x00") {
			t.Errorf("the environment exec passes on has no exact entry for %s", name)
		}
	}
}

// TestExecLooksUpTheCommandAfterLoading checks that a PATH parameter decides where a bare
// command name is found, as it does when the wrapper sources PATH and then runs exec.
func TestExecLooksUpTheCommandAfterLoading(t *testing.T) {
	execSetup(t)
	loadedDir := t.TempDir()
	loaded := filepath.Join(loadedDir, "only-on-the-loaded-path")
	if err := os.WriteFile(loaded, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fakeSSM{parameters: map[string]string{testPrefix + "PATH": loadedDir}}
	var clients int

	path, _, err := prepareExec(context.Background(), []string{"only-on-the-loaded-path"}, clientFor(f, &clients))
	if err != nil || path != loaded {
		t.Errorf("prepareExec = %q, %v; want %q", path, err, loaded)
	}
}

func TestExecDoesNotSearchPathForANameWithASlash(t *testing.T) {
	execSetup(t) // example-command is on PATH, but not at this path
	f, _ := seeded(1)
	var clients int
	missing := filepath.Join(t.TempDir(), "example-command")

	_, _, err := prepareExec(context.Background(), []string{missing}, clientFor(f, &clients))
	if err == nil || !strings.Contains(err.Error(), "secrets exec: cannot run "+missing) {
		t.Errorf("prepareExec error = %v, want one saying it cannot run %s", err, missing)
	}
}

// TestExecFailsBeforeRunning covers each way exec mode can fail. prepareExec returning an
// error means execMode prints it and exits 1 without running the command.
func TestExecFailsBeforeRunning(t *testing.T) {
	notExecutable := filepath.Join(t.TempDir(), "not-executable")
	if err := os.WriteFile(notExecutable, []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()

	for _, tc := range []struct {
		name      string
		args      []string
		setup     func(f *fakeSSM)
		clientErr error
		message   string
		noClient  bool // fails before it asks for an SSM client
	}{
		{name: "no command", args: []string{"--"}, message: "secrets exec: no command given", noClient: true},
		{name: "unknown option", args: []string{"-x", "example-command"}, message: "secrets exec: unknown option -x", noClient: true},
		{name: "no project", setup: func(*fakeSSM) { os.Unsetenv("PROJECT_NAME") }, message: "Failed to retrieve secrets: PROJECT_NAME environment variable not set", noClient: true},
		{name: "no environment", setup: func(*fakeSSM) { os.Unsetenv("ENVIRONMENT") }, message: "Failed to retrieve secrets: ENVIRONMENT environment variable not set", noClient: true},
		{name: "invalid name", setup: func(*fakeSSM) { os.Setenv("SECRETS_PARAMETERS", "PARAM_1,github-token") }, message: `Failed to retrieve secrets: Invalid SECRETS_PARAMETERS: not valid environment variable names: "github-token"`, noClient: true},
		{name: "no AWS config", clientErr: errors.New("no config"), message: "Failed to retrieve secrets: Error loading AWS config: no config"},
		{name: "access denied", setup: func(f *fakeSSM) {
			os.Setenv("SECRETS_PARAMETERS", "PARAM_1")
			f.getErr = &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized"}
		}, message: "Failed to retrieve secrets: Error fetching parameters: could not read PARAM_1 under /ecs/example-app/prod/"},
		{name: "missing named parameter", setup: func(*fakeSSM) { os.Setenv("SECRETS_PARAMETERS", "PARAM_1,MISSING") }, message: "Failed to retrieve secrets: Error fetching parameters: not found under /ecs/example-app/prod/: MISSING"},
		{name: "NUL byte in a value", setup: func(f *fakeSSM) { f.parameters[testPrefix+"PARAM_2"] = "secret-value\x00rest" }, message: "Failed to retrieve secrets: PARAM_2 holds a NUL byte"},
		{name: "command not on PATH", args: []string{"no-such-command"}, message: "secrets exec: cannot run no-such-command: executable file not found in $PATH"},
		{name: "command path missing", args: []string{"/no/such/command"}, message: "secrets exec: cannot run /no/such/command: "},
		{name: "command not executable", args: []string{notExecutable}, message: "secrets exec: cannot run " + notExecutable + ": permission denied"},
		{name: "command is a directory", args: []string{directory}, message: "secrets exec: cannot run " + directory + ": "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			execSetup(t)
			f, _ := seeded(3)
			if tc.setup != nil {
				tc.setup(f)
			}
			args := tc.args
			if args == nil {
				args = []string{"example-command"}
			}
			clients := 0
			newClient := clientFor(f, &clients)
			if tc.clientErr != nil {
				newClient = func(context.Context) (ssmClient, error) {
					clients++
					return nil, tc.clientErr
				}
			}

			path, argv, err := prepareExec(context.Background(), args, newClient)
			if err == nil {
				t.Fatalf("prepareExec = %q, %q; want an error", path, argv)
			}
			if !strings.HasPrefix(err.Error(), tc.message) {
				t.Errorf("error = %q, want it to start with %q", err, tc.message)
			}
			if strings.Contains(err.Error(), "secret-value") {
				t.Errorf("error %q leaks a parameter value", err)
			}
			if tc.noClient && (clients != 0 || f.byPathCalls != 0 || len(f.getCalls) != 0) {
				t.Errorf("asked for %d clients and made %d by-path and %d GetParameters calls; want none", clients, f.byPathCalls, len(f.getCalls))
			}
		})
	}
}
