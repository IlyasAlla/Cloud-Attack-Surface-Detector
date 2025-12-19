package providers

import (
	"context"
	"fmt"
	"skyscan/pkg/core"
	"skyscan/pkg/net"
	"strings"
)

// CloudService represents a discoverable cloud service
type CloudService struct {
	Provider      string   // AWS, Azure, GCP
	ServiceType   string   // e.g., "CloudFront", "API Gateway", "App Service"
	DomainPattern string   // e.g., "{keyword}.cloudfront.net"
	Endpoints     []string // Specific endpoints to check
	Severity      string   // Risk level if discovered
}

// AllCloudServices defines all targetable cloud services across providers
var AllCloudServices = []CloudService{
	// ============== AWS SERVICES ==============
	// Content Delivery
	{Provider: "AWS", ServiceType: "CloudFront", DomainPattern: "{keyword}.cloudfront.net", Severity: "MEDIUM"},

	// Compute
	{Provider: "AWS", ServiceType: "Elastic Beanstalk", DomainPattern: "{keyword}.elasticbeanstalk.com", Severity: "HIGH"},
	{Provider: "AWS", ServiceType: "App Runner", DomainPattern: "{keyword}.awsapprunner.com", Severity: "HIGH"},
	{Provider: "AWS", ServiceType: "Lambda Function URL", DomainPattern: "{keyword}.lambda-url.{region}.on.aws", Severity: "HIGH"},

	// API & Integration
	{Provider: "AWS", ServiceType: "API Gateway", DomainPattern: "{keyword}.execute-api.{region}.amazonaws.com", Severity: "HIGH"},
	{Provider: "AWS", ServiceType: "AppSync GraphQL", DomainPattern: "{keyword}.appsync-api.{region}.amazonaws.com", Severity: "HIGH"},

	// Containers
	{Provider: "AWS", ServiceType: "EKS", DomainPattern: "{keyword}.eks.amazonaws.com", Severity: "CRITICAL"},
	{Provider: "AWS", ServiceType: "ECS", DomainPattern: "{keyword}.ecs.{region}.amazonaws.com", Severity: "HIGH"},
	{Provider: "AWS", ServiceType: "ECR Public", DomainPattern: "public.ecr.aws/{keyword}", Severity: "MEDIUM"},

	// Databases (exposed endpoints)
	{Provider: "AWS", ServiceType: "RDS", DomainPattern: "{keyword}.{region}.rds.amazonaws.com", Severity: "CRITICAL"},
	{Provider: "AWS", ServiceType: "Redshift", DomainPattern: "{keyword}.{region}.redshift.amazonaws.com", Severity: "CRITICAL"},
	{Provider: "AWS", ServiceType: "DocumentDB", DomainPattern: "{keyword}.docdb.{region}.amazonaws.com", Severity: "CRITICAL"},
	{Provider: "AWS", ServiceType: "ElastiCache", DomainPattern: "{keyword}.cache.amazonaws.com", Severity: "CRITICAL"},

	// Messaging
	{Provider: "AWS", ServiceType: "IoT Core", DomainPattern: "{keyword}.iot.{region}.amazonaws.com", Severity: "HIGH"},
	{Provider: "AWS", ServiceType: "MQ", DomainPattern: "{keyword}.mq.{region}.amazonaws.com", Severity: "HIGH"},

	// Media
	{Provider: "AWS", ServiceType: "MediaPackage", DomainPattern: "{keyword}.mediapackage.{region}.amazonaws.com", Severity: "MEDIUM"},
	{Provider: "AWS", ServiceType: "MediaStore", DomainPattern: "{keyword}.data.mediastore.{region}.amazonaws.com", Severity: "MEDIUM"},

	// Networking
	{Provider: "AWS", ServiceType: "Global Accelerator", DomainPattern: "{keyword}.awsglobalaccelerator.com", Severity: "MEDIUM"},
	{Provider: "AWS", ServiceType: "Transfer Family SFTP", DomainPattern: "{keyword}.transfer.{region}.amazonaws.com", Severity: "HIGH"},

	// Developer Tools
	{Provider: "AWS", ServiceType: "Amplify", DomainPattern: "{keyword}.amplifyapp.com", Severity: "MEDIUM"},
	{Provider: "AWS", ServiceType: "CodeArtifact", DomainPattern: "{keyword}.codeartifact.{region}.amazonaws.com", Severity: "MEDIUM"},

	// ============== AZURE SERVICES ==============
	// Compute
	{Provider: "Azure", ServiceType: "App Service", DomainPattern: "{keyword}.azurewebsites.net", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "Functions", DomainPattern: "{keyword}.azurewebsites.net", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "Static Web Apps", DomainPattern: "{keyword}.azurestaticapps.net", Severity: "MEDIUM"},
	{Provider: "Azure", ServiceType: "Cloud Services", DomainPattern: "{keyword}.cloudapp.azure.com", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "Container Apps", DomainPattern: "{keyword}.containerapps.{region}.azurecontainerapps.io", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "Spring Apps", DomainPattern: "{keyword}.azuremicroservices.io", Severity: "HIGH"},

	// API & Integration
	{Provider: "Azure", ServiceType: "API Management", DomainPattern: "{keyword}.azure-api.net", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "Logic Apps", DomainPattern: "{keyword}.logic.azure.com", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "Event Grid", DomainPattern: "{keyword}.eventgrid.azure.net", Severity: "MEDIUM"},

	// Containers
	{Provider: "Azure", ServiceType: "Container Registry", DomainPattern: "{keyword}.azurecr.io", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "AKS", DomainPattern: "{keyword}.azmk8s.io", Severity: "CRITICAL"},

	// Databases
	{Provider: "Azure", ServiceType: "SQL Database", DomainPattern: "{keyword}.database.windows.net", Severity: "CRITICAL"},
	{Provider: "Azure", ServiceType: "CosmosDB", DomainPattern: "{keyword}.documents.azure.com", Severity: "CRITICAL"},
	{Provider: "Azure", ServiceType: "MySQL", DomainPattern: "{keyword}.mysql.database.azure.com", Severity: "CRITICAL"},
	{Provider: "Azure", ServiceType: "PostgreSQL", DomainPattern: "{keyword}.postgres.database.azure.com", Severity: "CRITICAL"},
	{Provider: "Azure", ServiceType: "Redis Cache", DomainPattern: "{keyword}.redis.cache.windows.net", Severity: "CRITICAL"},
	{Provider: "Azure", ServiceType: "MariaDB", DomainPattern: "{keyword}.mariadb.database.azure.com", Severity: "CRITICAL"},

	// CDN & Networking
	{Provider: "Azure", ServiceType: "CDN", DomainPattern: "{keyword}.azureedge.net", Severity: "MEDIUM"},
	{Provider: "Azure", ServiceType: "Front Door", DomainPattern: "{keyword}.azurefd.net", Severity: "MEDIUM"},
	{Provider: "Azure", ServiceType: "Traffic Manager", DomainPattern: "{keyword}.trafficmanager.net", Severity: "MEDIUM"},

	// Storage & File
	{Provider: "Azure", ServiceType: "File Share", DomainPattern: "{keyword}.file.core.windows.net", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "Queue Storage", DomainPattern: "{keyword}.queue.core.windows.net", Severity: "MEDIUM"},
	{Provider: "Azure", ServiceType: "Table Storage", DomainPattern: "{keyword}.table.core.windows.net", Severity: "MEDIUM"},
	{Provider: "Azure", ServiceType: "Data Lake", DomainPattern: "{keyword}.dfs.core.windows.net", Severity: "HIGH"},

	// DevOps & Developer
	{Provider: "Azure", ServiceType: "DevOps", DomainPattern: "{keyword}.visualstudio.com", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "DevOps Artifacts", DomainPattern: "{keyword}.pkgs.visualstudio.com", Severity: "MEDIUM"},
	{Provider: "Azure", ServiceType: "Key Vault", DomainPattern: "{keyword}.vault.azure.net", Severity: "CRITICAL"},

	// AI & ML
	{Provider: "Azure", ServiceType: "Cognitive Services", DomainPattern: "{keyword}.cognitiveservices.azure.com", Severity: "MEDIUM"},
	{Provider: "Azure", ServiceType: "OpenAI", DomainPattern: "{keyword}.openai.azure.com", Severity: "HIGH"},
	{Provider: "Azure", ServiceType: "ML Workspace", DomainPattern: "{keyword}.ml.azure.com", Severity: "HIGH"},

	// Communication
	{Provider: "Azure", ServiceType: "SignalR", DomainPattern: "{keyword}.service.signalr.net", Severity: "MEDIUM"},
	{Provider: "Azure", ServiceType: "Web PubSub", DomainPattern: "{keyword}.webpubsub.azure.com", Severity: "MEDIUM"},

	// ============== GCP SERVICES ==============
	// Compute
	{Provider: "GCP", ServiceType: "App Engine", DomainPattern: "{keyword}.appspot.com", Severity: "HIGH"},
	{Provider: "GCP", ServiceType: "Cloud Run", DomainPattern: "{keyword}.run.app", Severity: "HIGH"},
	{Provider: "GCP", ServiceType: "Cloud Functions", DomainPattern: "{region}-{keyword}.cloudfunctions.net", Severity: "HIGH"},

	// Firebase
	{Provider: "GCP", ServiceType: "Firebase Hosting", DomainPattern: "{keyword}.firebaseapp.com", Severity: "MEDIUM"},
	{Provider: "GCP", ServiceType: "Firebase Hosting Alt", DomainPattern: "{keyword}.web.app", Severity: "MEDIUM"},
	{Provider: "GCP", ServiceType: "Firebase RTDB", DomainPattern: "{keyword}.firebaseio.com", Severity: "HIGH"},
	{Provider: "GCP", ServiceType: "Firebase Auth", DomainPattern: "{keyword}.firebaseapp.com/__/auth/handler", Severity: "MEDIUM"},

	// Containers
	{Provider: "GCP", ServiceType: "GKE", DomainPattern: "{keyword}.{region}.gke.io", Severity: "CRITICAL"},
	{Provider: "GCP", ServiceType: "Container Registry", DomainPattern: "gcr.io/{keyword}", Severity: "HIGH"},
	{Provider: "GCP", ServiceType: "Artifact Registry", DomainPattern: "{region}-docker.pkg.dev/{keyword}", Severity: "HIGH"},

	// API & Integration
	{Provider: "GCP", ServiceType: "API Gateway", DomainPattern: "{keyword}.apigateway.{project}.cloud.goog", Severity: "HIGH"},
	{Provider: "GCP", ServiceType: "Endpoints", DomainPattern: "{keyword}.endpoints.{project}.cloud.goog", Severity: "HIGH"},

	// Databases
	{Provider: "GCP", ServiceType: "Cloud SQL", DomainPattern: "{region}:{keyword}.cloudsql.google.com", Severity: "CRITICAL"},
	{Provider: "GCP", ServiceType: "Firestore", DomainPattern: "firestore.googleapis.com/projects/{keyword}", Severity: "HIGH"},
	{Provider: "GCP", ServiceType: "BigQuery", DomainPattern: "bigquery.googleapis.com/bigquery/v2/projects/{keyword}", Severity: "HIGH"},
	{Provider: "GCP", ServiceType: "Bigtable", DomainPattern: "{keyword}.bigtable.googleapis.com", Severity: "CRITICAL"},
	{Provider: "GCP", ServiceType: "Spanner", DomainPattern: "spanner.googleapis.com/projects/{keyword}", Severity: "CRITICAL"},
	{Provider: "GCP", ServiceType: "Memorystore", DomainPattern: "{keyword}.redis.{region}.gce.googleapis.com", Severity: "CRITICAL"},

	// CDN & Networking
	{Provider: "GCP", ServiceType: "Cloud CDN", DomainPattern: "{keyword}.storage.googleapis.com", Severity: "MEDIUM"},

	// Pub/Sub & Messaging
	{Provider: "GCP", ServiceType: "Pub/Sub", DomainPattern: "pubsub.googleapis.com/projects/{keyword}", Severity: "MEDIUM"},

	// ML & AI
	{Provider: "GCP", ServiceType: "Vertex AI", DomainPattern: "{region}-aiplatform.googleapis.com/projects/{keyword}", Severity: "HIGH"},
	{Provider: "GCP", ServiceType: "AutoML", DomainPattern: "automl.googleapis.com/projects/{keyword}", Severity: "HIGH"},

	// Source & CI/CD
	{Provider: "GCP", ServiceType: "Cloud Source Repos", DomainPattern: "source.cloud.google.com/p/{keyword}", Severity: "HIGH"},
	{Provider: "GCP", ServiceType: "Cloud Build", DomainPattern: "cloudbuild.googleapis.com/projects/{keyword}", Severity: "MEDIUM"},

	// ============== OTHER CLOUD PROVIDERS ==============
	// DigitalOcean
	{Provider: "DigitalOcean", ServiceType: "App Platform", DomainPattern: "{keyword}.ondigitalocean.app", Severity: "HIGH"},
	{Provider: "DigitalOcean", ServiceType: "Spaces", DomainPattern: "{keyword}.digitaloceanspaces.com", Severity: "HIGH"},
	{Provider: "DigitalOcean", ServiceType: "Spaces Region", DomainPattern: "{keyword}.{region}.digitaloceanspaces.com", Severity: "HIGH"},

	// Heroku
	{Provider: "Heroku", ServiceType: "App", DomainPattern: "{keyword}.herokuapp.com", Severity: "HIGH"},

	// Alibaba Cloud
	{Provider: "Alibaba", ServiceType: "OSS", DomainPattern: "{keyword}.oss-{region}.aliyuncs.com", Severity: "HIGH"},
	{Provider: "Alibaba", ServiceType: "Function Compute", DomainPattern: "{keyword}.{region}.fc.aliyuncs.com", Severity: "HIGH"},

	// Oracle Cloud
	{Provider: "Oracle", ServiceType: "Object Storage", DomainPattern: "{keyword}.objectstorage.{region}.oci.customer-oci.com", Severity: "HIGH"},
	{Provider: "Oracle", ServiceType: "Functions", DomainPattern: "{keyword}.{region}.functions.oci.oraclecloud.com", Severity: "HIGH"},

	// IBM Cloud
	{Provider: "IBM", ServiceType: "Cloud Object Storage", DomainPattern: "{keyword}.s3.{region}.cloud-object-storage.appdomain.cloud", Severity: "HIGH"},
	{Provider: "IBM", ServiceType: "Code Engine", DomainPattern: "{keyword}.{region}.codeengine.appdomain.cloud", Severity: "HIGH"},

	// Netlify
	{Provider: "Netlify", ServiceType: "Site", DomainPattern: "{keyword}.netlify.app", Severity: "MEDIUM"},
	{Provider: "Netlify", ServiceType: "Functions", DomainPattern: "{keyword}.netlify.app/.netlify/functions/", Severity: "MEDIUM"},

	// Vercel
	{Provider: "Vercel", ServiceType: "Deployment", DomainPattern: "{keyword}.vercel.app", Severity: "MEDIUM"},

	// Render
	{Provider: "Render", ServiceType: "Web Service", DomainPattern: "{keyword}.onrender.com", Severity: "MEDIUM"},

	// Railway
	{Provider: "Railway", ServiceType: "App", DomainPattern: "{keyword}.up.railway.app", Severity: "MEDIUM"},

	// Fly.io
	{Provider: "Fly", ServiceType: "App", DomainPattern: "{keyword}.fly.dev", Severity: "MEDIUM"},

	// Cloudflare
	{Provider: "Cloudflare", ServiceType: "Pages", DomainPattern: "{keyword}.pages.dev", Severity: "MEDIUM"},
	{Provider: "Cloudflare", ServiceType: "Workers", DomainPattern: "{keyword}.workers.dev", Severity: "MEDIUM"},
	{Provider: "Cloudflare", ServiceType: "R2", DomainPattern: "{keyword}.r2.dev", Severity: "HIGH"},
}

// AWSRegions for region-specific enumeration
var AWSRegions = []string{
	"us-east-1", "us-east-2", "us-west-1", "us-west-2",
	"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2",
	"eu-north-1", "eu-south-1", "eu-south-2",
	"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
	"ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
	"ap-south-1", "ap-south-2", "ap-east-1",
	"sa-east-1", "ca-central-1", "me-south-1", "me-central-1",
	"af-south-1",
}

// AzureRegions for region-specific Azure enumeration
var AzureRegions = []string{
	"eastus", "eastus2", "westus", "westus2", "westus3",
	"centralus", "northcentralus", "southcentralus", "westcentralus",
	"canadacentral", "canadaeast",
	"brazilsouth", "brazilsoutheast",
	"northeurope", "westeurope", "uksouth", "ukwest",
	"francecentral", "francesouth", "germanywestcentral",
	"switzerlandnorth", "norwayeast", "swedencentral",
	"uaenorth", "southafricanorth", "qatarcentral",
	"australiaeast", "australiasoutheast", "australiacentral",
	"eastasia", "southeastasia", "japaneast", "japanwest",
	"koreacentral", "koreasouth", "centralindia", "westindia",
}

// GCPRegions for region-specific GCP enumeration
var GCPRegions = []string{
	"us-central1", "us-east1", "us-east4", "us-east5",
	"us-west1", "us-west2", "us-west3", "us-west4", "us-south1",
	"europe-west1", "europe-west2", "europe-west3", "europe-west4",
	"europe-west6", "europe-west8", "europe-west9", "europe-west12",
	"europe-north1", "europe-central2", "europe-southwest1",
	"asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3",
	"asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2",
	"australia-southeast1", "australia-southeast2",
	"southamerica-east1", "southamerica-west1",
	"northamerica-northeast1", "northamerica-northeast2",
	"me-central1", "me-west1",
}

// CloudAssetEnumerator discovers all cloud assets for a given keyword
type CloudAssetEnumerator struct {
	httpClient  *net.Client
	dnsResolver *net.DNSResolver
	config      *core.Config
}

func NewCloudAssetEnumerator(httpClient *net.Client, dnsResolver *net.DNSResolver) *CloudAssetEnumerator {
	return &CloudAssetEnumerator{
		httpClient:  httpClient,
		dnsResolver: dnsResolver,
	}
}

func (e *CloudAssetEnumerator) Init(config *core.Config) {
	e.config = config
}

// GenerateAllTargets creates all possible cloud service URLs for a keyword
func (e *CloudAssetEnumerator) GenerateAllTargets(ctx context.Context, keyword string, output chan<- CloudTarget) {
	for _, service := range AllCloudServices {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Generate base target
		url := strings.ReplaceAll(service.DomainPattern, "{keyword}", keyword)

		// Handle region-specific services
		if strings.Contains(url, "{region}") {
			var regions []string
			switch service.Provider {
			case "AWS":
				regions = AWSRegions
			case "Azure":
				regions = AzureRegions
			case "GCP":
				regions = GCPRegions
			default:
				regions = []string{"us-east-1"} // Default
			}

			for _, region := range regions {
				regionURL := strings.ReplaceAll(url, "{region}", region)
				output <- CloudTarget{
					URL:     fmt.Sprintf("https://%s", regionURL),
					Service: service,
					Region:  region,
				}
			}
		} else if strings.Contains(url, "{project}") {
			// GCP project-based services
			projectURL := strings.ReplaceAll(url, "{project}", keyword)
			output <- CloudTarget{
				URL:     fmt.Sprintf("https://%s", projectURL),
				Service: service,
			}
		} else {
			output <- CloudTarget{
				URL:     fmt.Sprintf("https://%s", url),
				Service: service,
			}
		}

		// Also apply mutations from config
		for _, mut := range e.config.Mutations {
			mutKeyword := keyword + "-" + mut
			mutURL := strings.ReplaceAll(service.DomainPattern, "{keyword}", mutKeyword)
			mutURL = strings.ReplaceAll(mutURL, "{region}", "us-east-1") // Default region for mutations
			mutURL = strings.ReplaceAll(mutURL, "{project}", mutKeyword)

			output <- CloudTarget{
				URL:     fmt.Sprintf("https://%s", mutURL),
				Service: service,
			}
		}
	}
}

// CloudTarget represents a target to check
type CloudTarget struct {
	URL     string
	Service CloudService
	Region  string
}

// CloudAssetResult represents a discovered cloud asset
type CloudAssetResult struct {
	URL         string            `json:"url"`
	Provider    string            `json:"provider"`
	ServiceType string            `json:"service_type"`
	Region      string            `json:"region,omitempty"`
	Status      int               `json:"status"`
	Severity    string            `json:"severity"`
	Accessible  bool              `json:"accessible"`
	Headers     map[string]string `json:"headers,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// CheckTarget validates if a cloud target exists and is accessible
func (e *CloudAssetEnumerator) CheckTarget(ctx context.Context, target CloudTarget) *CloudAssetResult {
	result := &CloudAssetResult{
		URL:         target.URL,
		Provider:    target.Service.Provider,
		ServiceType: target.Service.ServiceType,
		Region:      target.Region,
		Severity:    target.Service.Severity,
		Headers:     make(map[string]string),
	}

	// First try DNS check for efficiency
	// Extract hostname from URL
	hostname := strings.TrimPrefix(target.URL, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	hostname = strings.Split(hostname, "/")[0]

	dnsResult := e.dnsResolver.CheckExists(ctx, hostname)
	if !dnsResult.Exists {
		return nil // DNS doesn't resolve, skip HTTP check
	}

	// HTTP check
	status, _, err := e.httpClient.Check(target.URL)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Status = status

	// Classify accessibility based on status code
	switch status {
	case 200, 201, 202, 204:
		result.Accessible = true
	case 301, 302, 307, 308:
		result.Accessible = true // Redirect, still valid
	case 401, 403:
		result.Accessible = false // Exists but protected
	case 404:
		return nil // Not found, don't report
	default:
		result.Accessible = false
	}

	return result
}
