package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"al.essio.dev/pkg/shellescape"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// SSM permits '.' and '-' in a parameter name; bash rejects them in an identifier, and its
// "not a valid identifier" error echoes the whole assignment including the secret. Exec mode
// runs no shell but keeps the same rule, so both modes give a function the same variables.
var shellIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// GetParameters accepts at most 10 names per call.
const getParametersBatchSize = 10

// The value that means "named mode, but load nothing". The Terraform module sets it for a
// function that has its own role and no parameters, so the wrapper never falls back to
// reading by path, which that role can't do.
const noParameters = "none"

type ssmClient interface {
	ssm.GetParametersByPathAPIClient
	GetParameters(ctx context.Context, params *ssm.GetParametersInput, optFns ...func(*ssm.Options)) (*ssm.GetParametersOutput, error)
}

func env(environment string) string {
	switch environment {
	case "production":
		return "prod"
	case "staging":
		return "stage"
	case "development", "lab", "poc":
		return "lab"
	default:
		return "lab"
	}
}

// parseParameterNames reads SECRETS_PARAMETERS. It returns an empty list for "none" or an
// empty value, which still means named mode: the caller must not read by path.
func parseParameterNames(value string) ([]string, error) {
	if strings.TrimSpace(value) == noParameters {
		return []string{}, nil
	}
	names := make([]string, 0)
	seen := make(map[string]bool)
	invalid := make([]string, 0)
	for _, entry := range strings.Split(value, ",") {
		name := strings.TrimSpace(entry)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		// Skipping a bad name (as by-path mode does) would start the function without a
		// secret someone asked for by name. Refuse instead, so the mistake shows at deploy.
		if !shellIdentifier.MatchString(name) {
			invalid = append(invalid, fmt.Sprintf("%q", name))
			continue
		}
		names = append(names, name)
	}
	if len(invalid) > 0 {
		return nil, fmt.Errorf("not valid environment variable names: %s", strings.Join(invalid, ", "))
	}
	return names, nil
}

// fetchByPath loads every parameter directly under prefix. This is the default mode.
func fetchByPath(ctx context.Context, client ssmClient, prefix string) ([]types.Parameter, error) {
	parameters := make([]types.Parameter, 0)
	paginator := ssm.NewGetParametersByPathPaginator(client, &ssm.GetParametersByPathInput{
		Path:           aws.String(prefix),
		WithDecryption: aws.Bool(true),
	}, func(options *ssm.GetParametersByPathPaginatorOptions) {
		options.Limit = 10
	})
	for paginator.HasMorePages() {
		response, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		parameters = append(parameters, response.Parameters...)
	}
	return parameters, nil
}

// fetchByName loads exactly prefix+name for each name, and never reads by path, because a
// function with its own role is only allowed GetParameters on its listed names.
//
// Every listed name must come back. A missing one fails the whole load, so the function
// doesn't start without a secret it was promised. Errors name parameters, never values.
func fetchByName(ctx context.Context, client ssmClient, prefix string, names []string) ([]types.Parameter, error) {
	parameters := make([]types.Parameter, 0, len(names))
	missing := make([]string, 0)
	for start := 0; start < len(names); start += getParametersBatchSize {
		batch := names[start:min(start+getParametersBatchSize, len(names))]
		fullNames := make([]string, len(batch))
		for i, name := range batch {
			fullNames[i] = prefix + name
		}
		response, err := client.GetParameters(ctx, &ssm.GetParametersInput{
			Names:          fullNames,
			WithDecryption: aws.Bool(true),
		})
		if err != nil {
			// An AccessDenied covers the whole call, and SSM doesn't say which name it
			// refused, so name the batch.
			return nil, fmt.Errorf("could not read %s under %s: %w", strings.Join(batch, ", "), prefix, err)
		}
		// Count anything that didn't come back as missing, not only what SSM lists in
		// InvalidParameters, so a short response can't start the function without a secret.
		returned := make(map[string]bool, len(response.Parameters))
		for _, parameter := range response.Parameters {
			returned[aws.ToString(parameter.Name)] = true
		}
		for i, name := range batch {
			if !returned[fullNames[i]] {
				missing = append(missing, name)
			}
		}
		parameters = append(parameters, response.Parameters...)
	}
	// Keep going through every batch before failing, so one deploy shows every missing name.
	if len(missing) > 0 {
		return nil, fmt.Errorf("not found under %s: %s", prefix, strings.Join(missing, ", "))
	}
	return parameters, nil
}

// namedParameters reads SECRETS_PARAMETERS. Set (even to "" or "none") means named mode;
// unset keeps the by-path load.
func namedParameters() (names []string, named bool, err error) {
	value, named := os.LookupEnv("SECRETS_PARAMETERS")
	if !named {
		return nil, false, nil
	}
	names, err = parseParameterNames(value)
	return names, true, err
}

func fetch(ctx context.Context, client ssmClient, prefix string, names []string, named bool) ([]types.Parameter, error) {
	if named {
		return fetchByName(ctx, client, prefix, names)
	}
	return fetchByPath(ctx, client, prefix)
}

// settings is what both modes read from the environment.
type settings struct {
	project     string
	environment string
	names       []string
	named       bool
}

// prefix is the SSM path that holds the app's parameters.
func (s settings) prefix() string {
	return fmt.Sprintf("/ecs/%s/%s/", s.project, env(s.environment))
}

// readSettings reads PROJECT_NAME, ENVIRONMENT and SECRETS_PARAMETERS. Keep the wording of
// its errors: the wrapper has always logged them, so people search the logs for them.
func readSettings() (settings, error) {
	project, exists := os.LookupEnv("PROJECT_NAME")
	if !exists {
		return settings{}, errors.New("PROJECT_NAME environment variable not set")
	}
	environment, exists := os.LookupEnv("ENVIRONMENT")
	if !exists {
		return settings{}, errors.New("ENVIRONMENT environment variable not set")
	}
	names, named, err := namedParameters()
	if err != nil {
		return settings{}, fmt.Errorf("Invalid SECRETS_PARAMETERS: %w", err)
	}
	return settings{project: project, environment: environment, names: names, named: named}, nil
}

// newSSMClient builds the real client. Tests pass a fake in its place.
func newSSMClient(ctx context.Context) (ssmClient, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
	if err != nil {
		return nil, err
	}
	return ssm.NewFromConfig(cfg), nil
}

// loadParameters reads the app's parameters from SSM. Both modes go through here, so they
// load the same parameters and fail the same way.
func loadParameters(ctx context.Context, s settings, newClient func(context.Context) (ssmClient, error)) ([]types.Parameter, error) {
	client, err := newClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("Error loading AWS config: %w", err)
	}
	parameters, err := fetch(ctx, client, s.prefix(), s.names, s.named)
	if err != nil {
		return nil, fmt.Errorf("Error fetching parameters: %w", err)
	}
	return parameters, nil
}

// variable is one parameter as it lands in the environment.
type variable struct {
	name  string
	value string
}

// variables names each parameter by the part of its name after prefix, and skips a name
// that isn't a valid shell identifier. Both modes go through here, so a function gets the
// same variables whichever one starts it.
func variables(prefix string, parameters []types.Parameter) []variable {
	vars := make([]variable, 0, len(parameters))
	for _, parameter := range parameters {
		name := strings.TrimPrefix(aws.ToString(parameter.Name), prefix)
		if !shellIdentifier.MatchString(name) {
			fmt.Fprintf(os.Stderr, "Skipping %s: not a valid shell identifier\n", name)
			continue
		}
		vars = append(vars, variable{name: name, value: aws.ToString(parameter.Value)})
	}
	return vars
}

// writeExports writes one shell export per variable. It stops at the first write error.
func writeExports(w io.Writer, prefix string, parameters []types.Parameter) error {
	for _, v := range variables(prefix, parameters) {
		if _, err := fmt.Fprintf(w, "export %s=%s\n", v.name, shellescape.Quote(v.value)); err != nil {
			return err
		}
	}
	return nil
}

// commandLine returns the command and its arguments from what follows `exec`. A leading --
// is dropped. There are no options yet, so anything else that starts with - is refused
// rather than run, which leaves room to add options later without changing what an
// existing command line does.
func commandLine(args []string) ([]string, error) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	} else if len(args) > 0 && strings.HasPrefix(args[0], "-") {
		return nil, fmt.Errorf("secrets exec: unknown option %s. Usage: secrets exec [--] <command> [args...]", args[0])
	}
	if len(args) == 0 || args[0] == "" {
		return nil, errors.New("secrets exec: no command given. Usage: secrets exec [--] <command> [args...]")
	}
	return args, nil
}

// setEnvironment sets each variable in this process's environment, which exec hands to the
// command. A parameter replaces a variable that is already set, as it does when the wrapper
// sources its exports on top of the function's own environment.
func setEnvironment(vars []variable) error {
	for _, v := range vars {
		// An environment entry ends at a NUL byte, so the command would get a cut-off value.
		if strings.IndexByte(v.value, 0) >= 0 {
			return fmt.Errorf("%s holds a NUL byte, which can't go in an environment variable", v.name)
		}
		if err := os.Setenv(v.name, v.value); err != nil {
			return fmt.Errorf("could not set %s: %w", v.name, err)
		}
	}
	return nil
}

// prepareExec does everything exec mode needs before the exec itself: it checks the command
// line, loads the parameters into this process's environment and finds the command. It
// returns the path to run and the argv to give it.
func prepareExec(ctx context.Context, args []string, newClient func(context.Context) (ssmClient, error)) (string, []string, error) {
	argv, err := commandLine(args)
	if err != nil {
		return "", nil, err
	}
	// "Failed to retrieve secrets" is the phrase the wrapper logs, so one log search finds
	// a failed start in either mode.
	s, err := readSettings()
	if err != nil {
		return "", nil, fmt.Errorf("Failed to retrieve secrets: %w", err)
	}
	parameters, err := loadParameters(ctx, s, newClient)
	if err != nil {
		return "", nil, fmt.Errorf("Failed to retrieve secrets: %w", err)
	}
	if err := setEnvironment(variables(s.prefix(), parameters)); err != nil {
		return "", nil, fmt.Errorf("Failed to retrieve secrets: %w", err)
	}
	// Find the command after the parameters are set, so a PATH parameter counts, as it does
	// when the wrapper runs exec after source. LookPath only searches PATH for a name with
	// no slash; a path is checked as it is.
	path, err := exec.LookPath(argv[0])
	if err != nil {
		var lookErr *exec.Error
		if errors.As(err, &lookErr) {
			err = lookErr.Err
		}
		return "", nil, fmt.Errorf("secrets exec: cannot run %s: %w", argv[0], err)
	}
	return path, argv, nil
}

// execMode is `secrets exec [--] <command> [args...]`. It loads the parameters the same way
// the wrapper mode does, puts them straight into the environment, and then becomes the
// command. It needs no shell and writes no file, so it can start a function on an image
// that has no shell. Any failure exits 1 before the command runs, so the command never
// starts without its secrets.
func execMode(args []string) {
	path, argv, err := prepareExec(context.Background(), args, newSSMClient)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Exec replaces this process with the command, so it only returns if it failed.
	err = syscall.Exec(path, argv, os.Environ())
	fmt.Fprintf(os.Stderr, "secrets exec: cannot run %s: %v\n", argv[0], err)
	os.Exit(1)
}

// wrapperMode is what the binary does with no arguments, for secrets-wrapper: it writes the
// parameters to a file of shell exports and prints the file's path, which the wrapper
// sources. Errors print to stdout and exit 1, because the wrapper captures stdout and logs
// it as "Failed to retrieve secrets: ...".
func wrapperMode() {
	ctx := context.Background()
	s, err := readSettings()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// BUILD_NUMBER is optional: it is only a cache-filename component. v1 images
	// bake it at build time; pipeline-v2 images are environment-neutral and set no
	// build number. The /tmp cache is scoped to a single execution environment,
	// which never survives a code deploy, so a static fallback is safe.
	build, exists := os.LookupEnv("BUILD_NUMBER")
	if !exists {
		build = "0"
	}

	cacheDir := filepath.Join(os.TempDir(), "org.cru.secrets-lambda-cache")
	err = os.MkdirAll(cacheDir, 0755)
	if err != nil {
		fmt.Printf("Error creating cache directory: %v\n", err)
		os.Exit(1)
	}

	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s-%s-%s", s.project, s.environment, build))

	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		// Cache does not exist
		parameters, err := loadParameters(ctx, s, newSSMClient)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		file, err := os.Create(cacheFile)
		if err != nil {
			fmt.Printf("Error creating cache file: %v\n", err)
			os.Exit(1)
		}
		err = writeExports(file, s.prefix(), parameters)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			// Remove the short file, or the next start would find it and run without the
			// parameters that didn't make it in.
			os.Remove(cacheFile)
			fmt.Printf("Error writing cache file: %v\n", err)
			os.Exit(1)
		}
	}
	// Cache exists, use it
	fmt.Printf("%s", cacheFile)
	os.Exit(0)
}

func main() {
	// Any other arguments are ignored, as they always have been.
	if len(os.Args) > 1 && os.Args[1] == "exec" {
		execMode(os.Args[2:]) // never returns
	}
	wrapperMode()
}
