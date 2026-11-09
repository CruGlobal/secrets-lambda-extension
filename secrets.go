package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"al.essio.dev/pkg/shellescape"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
)

// SSM permits '.' and '-' in a parameter name; bash rejects them in an identifier, and its
// "not a valid identifier" error echoes the whole assignment including the secret.
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

// writeExports writes one shell export per parameter, named by the part of its name after
// prefix. Both modes go through here, so the environment they build looks the same.
func writeExports(w io.Writer, prefix string, parameters []types.Parameter) {
	for _, parameter := range parameters {
		key := strings.TrimPrefix(aws.ToString(parameter.Name), prefix)
		if !shellIdentifier.MatchString(key) {
			fmt.Fprintf(os.Stderr, "Skipping %s: not a valid shell identifier\n", key)
			continue
		}
		value := aws.ToString(parameter.Value)
		fmt.Fprintf(w, "export %s=%s\n", key, shellescape.Quote(value))
	}
}

func main() {
	ctx := context.Background()
	project, exists := os.LookupEnv("PROJECT_NAME")
	if !exists {
		fmt.Println("PROJECT_NAME environment variable not set")
		os.Exit(1)
	}
	environment, exists := os.LookupEnv("ENVIRONMENT")
	if !exists {
		fmt.Println("ENVIRONMENT environment variable not set")
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
	// Errors print to stdout and exit 1 like every other failure here, because
	// secrets-wrapper captures stdout and logs it as "Failed to retrieve secrets: ...".
	names, namedMode, err := namedParameters()
	if err != nil {
		fmt.Printf("Invalid SECRETS_PARAMETERS: %v\n", err)
		os.Exit(1)
	}

	cacheDir := filepath.Join(os.TempDir(), "org.cru.secrets-lambda-cache")
	err = os.MkdirAll(cacheDir, 0755)
	if err != nil {
		fmt.Printf("Error creating cache directory: %v\n", err)
		os.Exit(1)
	}

	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("%s-%s-%s", project, environment, build))

	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		// Cache does not exist
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
		if err != nil {
			fmt.Printf("Error loading AWS config: %v\n", err)
			os.Exit(1)
		}
		client := ssm.NewFromConfig(cfg)

		prefix := fmt.Sprintf("/ecs/%s/%s/", project, env(environment))
		parameters, err := fetch(ctx, client, prefix, names, namedMode)
		if err != nil {
			fmt.Printf("Error fetching parameters: %v\n", err)
			os.Exit(1)
		}
		file, err := os.Create(cacheFile)
		if err != nil {
			fmt.Printf("Error creating cache file: %v\n", err)
			os.Exit(1)
		}
		writeExports(file, prefix, parameters)
		file.Close()
	}
	// Cache exists, use it
	fmt.Printf("%s", cacheFile)
	os.Exit(0)
}
