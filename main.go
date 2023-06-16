package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"

	"github.com/operator-framework/operator-registry/alpha/property"
	"github.com/spf13/cobra"

	fbc "github.com/operator-framework/operator-registry/alpha/declcfg"
)

type Channel struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Link struct {
	Name string `json:"name" yaml:"name"`
	URL  string `json:"url" yaml:"url"`
}

type SecurityReportSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

type Version struct {
	Version string `json:"version"`
	TS      int64  `json:"ts"`
}

type ContainerImage struct {
	Name        string   `json:"name" yaml:"name"`
	Image       string   `json:"image" yaml:"image"`
	Whitelisted bool     `json:"whitelisted" yaml:"whitelisted"`
	Platforms   []string `json:"platforms" yaml:"platforms"`
}

type Change struct {
	Kind        string  `json:"kind,omitempty"`
	Description string  `json:"description"`
	Links       []*Link `json:"links,omitempty"`
}

type Maintainer struct {
	MaintainerID string `json:"maintainer_id"`
	Name         string `json:"name" yaml:"name"`
	Email        string `json:"email" yaml:"email"`
}

type Recommendation struct {
	URL string `json:"url" yaml:"url"`
}

type Screenshot struct {
	Title string `json:"title" yaml:"title"`
	URL   string `json:"url" yaml:"url"`
}

type SignKey struct {
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	URL         string `json:"url" yaml:"url"`
}

type Repository struct {
	//RepositoryID            string          `json:"repository_id"`
	Name string `json:"name"`
	//DisplayName             string          `json:"display_name"`
	//URL                     string          `json:"url"`
	//Branch                  string          `json:"branch"`
	//Private                 bool            `json:"private"`
	//AuthUser                string          `json:"auth_user"`
	//AuthPass                string          `json:"auth_pass"`
	//Digest                  string          `json:"digest"`
	Kind int64 `json:"kind"`
	//UserID                  string          `json:"user_id"`
	//UserAlias               string          `json:"user_alias"`
	//OrganizationID          string          `json:"organization_id"`
	//OrganizationName        string          `json:"organization_name"`
	//OrganizationDisplayName string          `json:"organization_display_name"`
	//LastScanningErrors      string          `json:"last_scanning_errors"`
	//LastTrackingErrors      string          `json:"last_tracking_errors"`
	//VerifiedPublisher       bool            `json:"verified_publisher"`
	//Official                bool            `json:"official"`
	//CNCF                    bool            `json:"cncf"`
	//Disabled                bool            `json:"disabled"`
	//ScannerDisabled         bool            `json:"scanner_disabled"`
	//Data                    json.RawMessage `json:"data,omitempty"`
}

const (
	HelmRepositoryKind int64 = 0
)

type PackageStats struct {
	Subscriptions int `json:"subscriptions"`
	Webhooks      int `json:"webhooks"`
}

type Organization struct {
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	DisplayName    string `json:"display_name"`
	Description    string `json:"description"`
	HomeURL        string `json:"home_url"`
	LogoImageID    string `json:"logo_image_id"`
}

type Package struct {
	//PackageID                      string                 `json:"package_id" hash:"ignore"`
	//Name                           string                 `json:"name"`
	NormalizedName string `json:"normalized_name" hash:"ignore"`
	//AlternativeName                string                 `json:"alternative_name"`
	//Category                       int64                  `json:"category"`
	//LogoURL                        string                 `json:"logo_url"`
	//LogoImageID                    string                 `json:"logo_image_id" hash:"ignore"`
	IsOperator bool `json:"is_operator"`
	//Official                       bool                   `json:"official" hash:"ignore"`
	//CNCF                           bool                   `json:"cncf" hash:"ignore"`
	//Channels       []*Channel `json:"channels"`
	//DefaultChannel string     `json:"default_channel"`
	//DisplayName                    string                 `json:"display_name"`
	Description string `json:"description"`
	//Keywords                       []string               `json:"keywords"`
	//HomeURL                        string                 `json:"home_url"`
	//Readme                         string                 `json:"readme"`
	//Install                        string                 `json:"install"`
	//Links                          []*Link                `json:"links"`
	//Capabilities                   string                 `json:"capabilities"`
	//CRDs                           []interface{}          `json:"crds"`
	//CRDsExamples                   []interface{}          `json:"crds_examples"`
	//SecurityReportSummary          *SecurityReportSummary `json:"security_report_summary" hash:"ignore"`
	//SecurityReportCreatedAt        int64                  `json:"security_report_created_at,omitempty" hash:"ignore"`
	//Data                           map[string]interface{} `json:"data"`
	Version           string     `json:"version"`
	AvailableVersions []*Version `json:"available_versions" hash:"ignore"`
	//AppVersion                     string                 `json:"app_version"`
	//Digest                         string                 `json:"digest"`
	//Deprecated                     bool                   `json:"deprecated"`
	//License                        string                 `json:"license"`
	//Signed                         bool                   `json:"signed"`
	//Signatures                     []string               `json:"signatures"`
	ContentURL string `json:"content_url"`
	//ContainersImages               []*ContainerImage      `json:"containers_images"`
	//AllContainersImagesWhitelisted bool                   `json:"all_containers_images_whitelisted" hash:"ignore"`
	//Provider                       string                 `json:"provider"`
	//HasValuesSchema                bool                   `json:"has_values_schema" hash:"ignore"`
	//ValuesSchema                   json.RawMessage        `json:"values_schema,omitempty"`
	//HasChangelog                   bool                   `json:"has_changelog" hash:"ignore"`
	//Changes                        []*Change              `json:"changes"`
	//ContainsSecurityUpdates        bool                   `json:"contains_security_updates"`
	//Prerelease                     bool                   `json:"prerelease"`
	//Maintainers                    []*Maintainer          `json:"maintainers"`
	//Recommendations                []*Recommendation      `json:"recommendations"`
	//Screenshots                    []*Screenshot          `json:"screenshots"`
	//SignKey                        *SignKey               `json:"sign_key"`
	Repository *Repository `json:"repository" hash:"ignore"`
	//TS                             int64                  `json:"ts,omitempty" hash:"ignore"`
	//Stats                          *PackageStats          `json:"stats" hash:"ignore"`
	//ProductionOrganizations        []*Organization        `json:"production_organizations" hash:"ignore"`
	//RelativePath                   string                 `json:"relative_path"`
}

func main() {
	var repo, pkg, version, output string
	cmd := &cobra.Command{
		Use:   "",
		Short: "Generate FBC from an artifacthub.io helm repository",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(repo) == 0 {
				return fmt.Errorf("repository name cannot be empty")
			}
			if len(pkg) == 0 {
				return fmt.Errorf("package name cannot be empty")
			}
			var write func(fbc.DeclarativeConfig, io.Writer) error
			switch output {
			case "yaml":
				write = fbc.WriteYAML
			case "json":
				write = fbc.WriteJSON
			default:
				log.Fatalf("invalid --output value %q, expected (json|yaml)", output)
			}

			opName := fmt.Sprintf("%s/%s/%s", repo, pkg, version)
			ahPkg, err := fetchPackage(fmt.Sprintf("https://artifacthub.io/api/v1/packages/helm/%s", opName))
			if err != nil {
				return err
			}

			ahFBC, err := fbcForAHPackage(ahPkg, len(version) == 0)
			if err != nil {
				return err
			}

			if err := write(*ahFBC, os.Stdout); err != nil {
				log.Fatal(err)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&repo, "repository", "r", "", "The artifacthub helm repository to render")
	cmd.Flags().StringVarP(&pkg, "package", "p", "", "The artifacthub helm package to render")
	cmd.Flags().StringVarP(&version, "version", "v", "", "The artifacthub helm package version to render")
	cmd.Flags().StringVarP(&output, "output", "o", "json", "Output format (json|yaml)")

	if err := cmd.Execute(); err != nil {
		fmt.Printf("error rendering repository: %v", err)
		os.Exit(1)
	}

}

func fetchPackage(repoURL string) (*Package, error) {
	resp, err := http.Get(repoURL)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("invalid operator %s", repoURL)
	}
	ahPkg := &Package{}
	err = json.Unmarshal(body, ahPkg)
	if err != nil {
		return nil, err
	}

	if !ahPkg.IsOperator {
		return nil, fmt.Errorf("%s is not an operator", repoURL)
	}

	if ahPkg.Repository.Kind != HelmRepositoryKind {
		return nil, fmt.Errorf("%s is not an artifacthub helm repository", repoURL)
	}

	return ahPkg, nil
}

func fbcForAHPackage(p *Package, allVersions bool) (*fbc.DeclarativeConfig, error) {
	ahFBC := fbc.DeclarativeConfig{}
	pkgProp, err := json.Marshal(property.Package{
		PackageName: p.NormalizedName,
		Version:     p.Version,
	})
	if err != nil {
		return nil, err
	}
	bundles := []fbc.Bundle{{
		Schema:  fbc.SchemaBundle,
		Name:    fmt.Sprintf("%s.v%s", p.NormalizedName, p.Version),
		Package: p.NormalizedName,
		Image:   p.ContentURL,
		Properties: []property.Property{
			{
				Type:  property.TypePackage,
				Value: pkgProp,
			},
			{
				Type:  TypeMediaType,
				Value: json.RawMessage(MediaTypeHelm),
			},
		},
		//RelatedImages: nil,
		//CsvJSON:       "",
		//Objects:       nil,
	}}

	if allVersions {
		ahFBC.Packages = []fbc.Package{{
			Schema:         fbc.SchemaPackage,
			Name:           p.NormalizedName,
			DefaultChannel: "stable",
			Description:    p.Description,
		}}

		var versions []string
		for _, v := range p.AvailableVersions {
			if v != nil {
				versions = append(versions, v.Version)
				if p.Version != v.Version {
					vPkg, err := fetchPackage(fmt.Sprintf("https://artifacthub.io/api/v1/packages/helm/%s/%s/%s", p.Repository.Name, p.NormalizedName, v.Version))
					if err != nil {
						return nil, err
					}
					pkgProp, err := json.Marshal(property.Package{
						PackageName: p.NormalizedName,
						Version:     vPkg.Version,
					})
					if err != nil {
						return nil, err
					}
					bundles = append(bundles, fbc.Bundle{
						Schema:  fbc.SchemaBundle,
						Name:    fmt.Sprintf("%s.v%s", p.NormalizedName, vPkg.Version),
						Package: p.NormalizedName,
						Image:   p.ContentURL,
						Properties: []property.Property{
							{
								Type:  property.TypePackage,
								Value: pkgProp,
							},
							{
								Type:  TypeMediaType,
								Value: json.RawMessage(MediaTypeHelm),
							},
						},
						//RelatedImages: nil,
						//CsvJSON:       "",
						//Objects:       nil,
					})
				}
			}
		}

		sortChannelVersions(versions)

		var entries []fbc.ChannelEntry
		for i := range versions {
			if i == 0 {
				entries = append(entries, fbc.ChannelEntry{
					Name: fmt.Sprintf("%s.v%s", p.NormalizedName, versions[i]),
				})
				continue
			}
			entries = append(entries, fbc.ChannelEntry{
				Name:     fmt.Sprintf("%s.v%s", p.NormalizedName, versions[i]),
				Replaces: fmt.Sprintf("%s.v%s", p.NormalizedName, versions[i-1]),
			})
		}

		ahFBC.Channels = []fbc.Channel{{
			Schema:  fbc.SchemaChannel,
			Name:    "stable",
			Package: p.NormalizedName,
			Entries: entries,
		}}

	}
	ahFBC.Bundles = bundles

	return &ahFBC, nil
}

func sortChannelVersions(v []string) []string {
	sort.Strings(v)
	return v
}

const TypeMediaType = "olm.bundle.mediatype"
const MediaTypeHelm = `"helm+v0"`
