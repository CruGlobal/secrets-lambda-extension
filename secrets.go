package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

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
	build, exists := os.LookupEnv("BUILD_NUMBER")
	if !exists {
		fmt.Println("BUILD_NUMBER environment variable not set")
		os.Exit(1)
	}

	cacheFile := filepath.Join(os.TempDir(), "secrets-cache", fmt.Sprintf("%s-%s-%s", project, environment, build))

	if _, err := os.Stat(cacheFile); os.IsNotExist(err) {
		// Cache does not exist
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion("us-east-1"))
		if err != nil {
			fmt.Printf("Error loading AWS config: %v\n", err)
			os.Exit(1)
		}
		client := ssm.NewFromConfig(cfg)

		prefix := fmt.Sprintf("/ecs/%s/%s/", project, env(environment))
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
				fmt.Printf("Error fetching parameters: %v\n", err)
				os.Exit(1)
			}
			for _, parameter := range response.Parameters {
				tagsResponse, err := client.ListTagsForResource(ctx, &ssm.ListTagsForResourceInput{
					ResourceType: ssmtypes.ResourceTypeForTaggingParameter,
					ResourceId:   parameter.Name,
				})
				if err != nil {
					fmt.Printf("Error fetching parameters: %v\n", err)
					os.Exit(1)
				}
				for _, tag := range tagsResponse.TagList {
					if tag.Key == aws.String("param_type") {
						if *tag.Value == "RUNTIME" || *tag.Value == "ALL" {
							parameters = append(parameters, parameter)
						}
					}
				}
			}
		}
		file, err := os.Create(cacheFile)
		if err != nil {
			fmt.Printf("Error creating cache file: %v\n", err)
			os.Exit(1)
		}
		for _, parameter := range parameters {
			key := strings.TrimPrefix(aws.ToString(parameter.Name), prefix)
			value := aws.ToString(parameter.Value)
			fmt.Fprintf(file, "export %s=%s\n", key, value)
		}
		file.Close()
	}
	// Cache exists, use it
	fmt.Printf("%s", cacheFile)
	os.Exit(0)
}
