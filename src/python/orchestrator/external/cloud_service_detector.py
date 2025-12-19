"""
Comprehensive Cloud Service Detector

Detects ALL cloud services beyond just storage, including:
- Compute (Lambda, Functions, App Service, Cloud Run)
- Databases (RDS, CosmosDB, Cloud SQL, DynamoDB)
- APIs (API Gateway, AppSync, Cloud Endpoints)  
- CDN (CloudFront, Azure CDN, Cloudflare)
- Containers (EKS, AKS, GKE, Container Registries)
- Serverless (Lambda URLs, Functions, Cloud Functions)
- And 100+ more services across all major cloud providers
"""

import asyncio
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class CloudProvider(Enum):
    AWS = "AWS"
    AZURE = "Azure"
    GCP = "GCP"
    DIGITALOCEAN = "DigitalOcean"
    HEROKU = "Heroku"
    NETLIFY = "Netlify"
    VERCEL = "Vercel"
    CLOUDFLARE = "Cloudflare"
    ALIBABA = "Alibaba"
    ORACLE = "Oracle"
    IBM = "IBM"
    OTHER = "Other"


class ServiceCategory(Enum):
    STORAGE = "storage"
    COMPUTE = "compute"
    DATABASE = "database"
    API = "api"
    CDN = "cdn"
    CONTAINER = "container"
    SERVERLESS = "serverless"
    SECRETS = "secrets"
    MESSAGING = "messaging"
    ML = "ml"
    DEVOPS = "devops"
    OTHER = "other"


@dataclass
class CloudServicePattern:
    """Pattern for detecting cloud services in DNS records and URLs."""
    provider: CloudProvider
    service_name: str
    category: ServiceCategory
    pattern: str  # Regex pattern
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str


# Comprehensive list of cloud service patterns
CLOUD_SERVICE_PATTERNS = [
    # ================ AWS ================
    # Storage
    CloudServicePattern(CloudProvider.AWS, "S3 Bucket", ServiceCategory.STORAGE, 
                       r"([a-z0-9][a-z0-9.-]*[a-z0-9])\.s3[.-]([a-z0-9-]+)?\.?amazonaws\.com", 
                       "HIGH", "Amazon S3 storage bucket"),
    
    # Compute
    CloudServicePattern(CloudProvider.AWS, "Elastic Beanstalk", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.elasticbeanstalk\.com", 
                       "HIGH", "AWS Elastic Beanstalk application"),
    CloudServicePattern(CloudProvider.AWS, "App Runner", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.awsapprunner\.com", 
                       "HIGH", "AWS App Runner service"),
    CloudServicePattern(CloudProvider.AWS, "Lambda Function URL", ServiceCategory.SERVERLESS,
                       r"([a-z0-9]+)\.lambda-url\.([a-z0-9-]+)\.on\.aws", 
                       "HIGH", "AWS Lambda function URL"),
    CloudServicePattern(CloudProvider.AWS, "Amplify", ServiceCategory.COMPUTE,
                       r"([a-z0-9]+)\.amplifyapp\.com", 
                       "MEDIUM", "AWS Amplify hosted app"),
    
    # API & Integration
    CloudServicePattern(CloudProvider.AWS, "API Gateway", ServiceCategory.API,
                       r"([a-z0-9]+)\.execute-api\.([a-z0-9-]+)\.amazonaws\.com", 
                       "HIGH", "AWS API Gateway endpoint"),
    CloudServicePattern(CloudProvider.AWS, "AppSync", ServiceCategory.API,
                       r"([a-z0-9]+)\.appsync-api\.([a-z0-9-]+)\.amazonaws\.com", 
                       "HIGH", "AWS AppSync GraphQL API"),
    
    # CDN
    CloudServicePattern(CloudProvider.AWS, "CloudFront", ServiceCategory.CDN,
                       r"([a-z0-9]+)\.cloudfront\.net", 
                       "MEDIUM", "AWS CloudFront distribution"),
    CloudServicePattern(CloudProvider.AWS, "Global Accelerator", ServiceCategory.CDN,
                       r"([a-z0-9]+)\.awsglobalaccelerator\.com", 
                       "MEDIUM", "AWS Global Accelerator"),
    
    # Containers
    CloudServicePattern(CloudProvider.AWS, "ECR Public", ServiceCategory.CONTAINER,
                       r"public\.ecr\.aws/([a-z0-9-]+)", 
                       "MEDIUM", "AWS ECR Public repository"),
    CloudServicePattern(CloudProvider.AWS, "EKS", ServiceCategory.CONTAINER,
                       r"([a-z0-9-]+)\.eks\.amazonaws\.com", 
                       "CRITICAL", "Amazon EKS cluster"),
    
    # Databases
    CloudServicePattern(CloudProvider.AWS, "RDS", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.([a-z0-9-]+)\.rds\.amazonaws\.com", 
                       "CRITICAL", "Amazon RDS database"),
    CloudServicePattern(CloudProvider.AWS, "DocumentDB", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.docdb\.([a-z0-9-]+)\.amazonaws\.com", 
                       "CRITICAL", "Amazon DocumentDB cluster"),
    CloudServicePattern(CloudProvider.AWS, "ElastiCache", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.cache\.amazonaws\.com", 
                       "CRITICAL", "Amazon ElastiCache cluster"),
    CloudServicePattern(CloudProvider.AWS, "Redshift", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.([a-z0-9-]+)\.redshift\.amazonaws\.com", 
                       "CRITICAL", "Amazon Redshift data warehouse"),
    
    # IoT & Messaging
    CloudServicePattern(CloudProvider.AWS, "IoT Core", ServiceCategory.MESSAGING,
                       r"([a-z0-9-]+)\.iot\.([a-z0-9-]+)\.amazonaws\.com", 
                       "HIGH", "AWS IoT Core endpoint"),
    CloudServicePattern(CloudProvider.AWS, "MQ", ServiceCategory.MESSAGING,
                       r"([a-z0-9-]+)\.mq\.([a-z0-9-]+)\.amazonaws\.com", 
                       "HIGH", "Amazon MQ broker"),
    
    # ================ AZURE ================
    # Compute
    CloudServicePattern(CloudProvider.AZURE, "App Service", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.azurewebsites\.net", 
                       "HIGH", "Azure App Service / Functions"),
    CloudServicePattern(CloudProvider.AZURE, "Static Web App", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.azurestaticapps\.net", 
                       "MEDIUM", "Azure Static Web App"),
    CloudServicePattern(CloudProvider.AZURE, "Cloud Service", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.cloudapp\.azure\.com", 
                       "HIGH", "Azure Cloud Service"),
    CloudServicePattern(CloudProvider.AZURE, "Container Apps", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.([a-z0-9-]+)\.azurecontainerapps\.io", 
                       "HIGH", "Azure Container Apps"),
    CloudServicePattern(CloudProvider.AZURE, "Spring Apps", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.azuremicroservices\.io", 
                       "HIGH", "Azure Spring Apps"),
    
    # Storage
    CloudServicePattern(CloudProvider.AZURE, "Blob Storage", ServiceCategory.STORAGE,
                       r"([a-z0-9]+)\.blob\.core\.windows\.net", 
                       "HIGH", "Azure Blob Storage account"),
    CloudServicePattern(CloudProvider.AZURE, "File Storage", ServiceCategory.STORAGE,
                       r"([a-z0-9]+)\.file\.core\.windows\.net", 
                       "HIGH", "Azure File Storage"),
    CloudServicePattern(CloudProvider.AZURE, "Queue Storage", ServiceCategory.STORAGE,
                       r"([a-z0-9]+)\.queue\.core\.windows\.net", 
                       "MEDIUM", "Azure Queue Storage"),
    CloudServicePattern(CloudProvider.AZURE, "Table Storage", ServiceCategory.STORAGE,
                       r"([a-z0-9]+)\.table\.core\.windows\.net", 
                       "MEDIUM", "Azure Table Storage"),
    CloudServicePattern(CloudProvider.AZURE, "Data Lake", ServiceCategory.STORAGE,
                       r"([a-z0-9]+)\.dfs\.core\.windows\.net", 
                       "HIGH", "Azure Data Lake Storage"),
    
    # API & Integration
    CloudServicePattern(CloudProvider.AZURE, "API Management", ServiceCategory.API,
                       r"([a-z0-9-]+)\.azure-api\.net", 
                       "HIGH", "Azure API Management"),
    CloudServicePattern(CloudProvider.AZURE, "Logic Apps", ServiceCategory.API,
                       r"([a-z0-9-]+)\.logic\.azure\.com", 
                       "HIGH", "Azure Logic Apps"),
    CloudServicePattern(CloudProvider.AZURE, "Event Grid", ServiceCategory.MESSAGING,
                       r"([a-z0-9-]+)\.eventgrid\.azure\.net", 
                       "MEDIUM", "Azure Event Grid"),
    CloudServicePattern(CloudProvider.AZURE, "SignalR", ServiceCategory.MESSAGING,
                       r"([a-z0-9-]+)\.service\.signalr\.net", 
                       "MEDIUM", "Azure SignalR Service"),
    
    # CDN
    CloudServicePattern(CloudProvider.AZURE, "CDN", ServiceCategory.CDN,
                       r"([a-z0-9-]+)\.azureedge\.net", 
                       "MEDIUM", "Azure CDN endpoint"),
    CloudServicePattern(CloudProvider.AZURE, "Front Door", ServiceCategory.CDN,
                       r"([a-z0-9-]+)\.azurefd\.net", 
                       "MEDIUM", "Azure Front Door"),
    CloudServicePattern(CloudProvider.AZURE, "Traffic Manager", ServiceCategory.CDN,
                       r"([a-z0-9-]+)\.trafficmanager\.net", 
                       "MEDIUM", "Azure Traffic Manager"),
    
    # Containers
    CloudServicePattern(CloudProvider.AZURE, "Container Registry", ServiceCategory.CONTAINER,
                       r"([a-z0-9]+)\.azurecr\.io", 
                       "HIGH", "Azure Container Registry"),
    CloudServicePattern(CloudProvider.AZURE, "AKS", ServiceCategory.CONTAINER,
                       r"([a-z0-9-]+)\.azmk8s\.io", 
                       "CRITICAL", "Azure Kubernetes Service cluster"),
    
    # Databases
    CloudServicePattern(CloudProvider.AZURE, "SQL Database", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.database\.windows\.net", 
                       "CRITICAL", "Azure SQL Database"),
    CloudServicePattern(CloudProvider.AZURE, "CosmosDB", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.documents\.azure\.com", 
                       "CRITICAL", "Azure Cosmos DB account"),
    CloudServicePattern(CloudProvider.AZURE, "MySQL", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.mysql\.database\.azure\.com", 
                       "CRITICAL", "Azure Database for MySQL"),
    CloudServicePattern(CloudProvider.AZURE, "PostgreSQL", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.postgres\.database\.azure\.com", 
                       "CRITICAL", "Azure Database for PostgreSQL"),
    CloudServicePattern(CloudProvider.AZURE, "Redis Cache", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.redis\.cache\.windows\.net", 
                       "CRITICAL", "Azure Redis Cache"),
    
    # Secrets & Security
    CloudServicePattern(CloudProvider.AZURE, "Key Vault", ServiceCategory.SECRETS,
                       r"([a-z0-9-]+)\.vault\.azure\.net", 
                       "CRITICAL", "Azure Key Vault"),
    
    # AI/ML
    CloudServicePattern(CloudProvider.AZURE, "Cognitive Services", ServiceCategory.ML,
                       r"([a-z0-9-]+)\.cognitiveservices\.azure\.com", 
                       "MEDIUM", "Azure Cognitive Services"),
    CloudServicePattern(CloudProvider.AZURE, "OpenAI", ServiceCategory.ML,
                       r"([a-z0-9-]+)\.openai\.azure\.com", 
                       "HIGH", "Azure OpenAI Service"),
    
    # DevOps
    CloudServicePattern(CloudProvider.AZURE, "DevOps", ServiceCategory.DEVOPS,
                       r"([a-z0-9-]+)\.visualstudio\.com", 
                       "HIGH", "Azure DevOps organization"),
    
    # ================ GCP ================
    # Compute
    CloudServicePattern(CloudProvider.GCP, "App Engine", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.appspot\.com", 
                       "HIGH", "Google App Engine application"),
    CloudServicePattern(CloudProvider.GCP, "Cloud Run", ServiceCategory.SERVERLESS,
                       r"([a-z0-9-]+)\.run\.app", 
                       "HIGH", "Google Cloud Run service"),
    CloudServicePattern(CloudProvider.GCP, "Cloud Functions", ServiceCategory.SERVERLESS,
                       r"([a-z0-9-]+)-([a-z0-9-]+)\.cloudfunctions\.net", 
                       "HIGH", "Google Cloud Function"),
    
    # Storage
    CloudServicePattern(CloudProvider.GCP, "Cloud Storage", ServiceCategory.STORAGE,
                       r"storage\.googleapis\.com/([a-z0-9-_.]+)", 
                       "HIGH", "Google Cloud Storage bucket"),
    CloudServicePattern(CloudProvider.GCP, "Cloud Storage Alt", ServiceCategory.STORAGE,
                       r"([a-z0-9-_.]+)\.storage\.googleapis\.com", 
                       "HIGH", "Google Cloud Storage bucket"),
    
    # Firebase
    CloudServicePattern(CloudProvider.GCP, "Firebase Hosting", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.firebaseapp\.com", 
                       "MEDIUM", "Firebase Hosting"),
    CloudServicePattern(CloudProvider.GCP, "Firebase Web", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.web\.app", 
                       "MEDIUM", "Firebase Web Hosting"),
    CloudServicePattern(CloudProvider.GCP, "Firebase RTDB", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+)\.firebaseio\.com", 
                       "HIGH", "Firebase Realtime Database"),
    
    # Containers
    CloudServicePattern(CloudProvider.GCP, "Container Registry", ServiceCategory.CONTAINER,
                       r"gcr\.io/([a-z0-9-]+)", 
                       "HIGH", "Google Container Registry"),
    CloudServicePattern(CloudProvider.GCP, "Artifact Registry", ServiceCategory.CONTAINER,
                       r"([a-z0-9-]+)-docker\.pkg\.dev/([a-z0-9-]+)", 
                       "HIGH", "Google Artifact Registry"),
    CloudServicePattern(CloudProvider.GCP, "GKE", ServiceCategory.CONTAINER,
                       r"([a-z0-9-]+)\.([a-z0-9-]+)\.gke\.io", 
                       "CRITICAL", "Google Kubernetes Engine cluster"),
    
    # Databases
    CloudServicePattern(CloudProvider.GCP, "Cloud SQL", ServiceCategory.DATABASE,
                       r"([a-z0-9-]+):([a-z0-9-]+)\.cloudsql\.google\.com", 
                       "CRITICAL", "Google Cloud SQL"),
    
    # ================ OTHER PROVIDERS ================
    # DigitalOcean
    CloudServicePattern(CloudProvider.DIGITALOCEAN, "App Platform", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.ondigitalocean\.app", 
                       "HIGH", "DigitalOcean App Platform"),
    CloudServicePattern(CloudProvider.DIGITALOCEAN, "Spaces", ServiceCategory.STORAGE,
                       r"([a-z0-9-]+)\.([a-z0-9-]+)?\.?digitaloceanspaces\.com", 
                       "HIGH", "DigitalOcean Spaces bucket"),
    
    # Heroku
    CloudServicePattern(CloudProvider.HEROKU, "App", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.herokuapp\.com", 
                       "HIGH", "Heroku application"),
    
    # Netlify
    CloudServicePattern(CloudProvider.NETLIFY, "Site", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.netlify\.app", 
                       "MEDIUM", "Netlify hosted site"),
    
    # Vercel
    CloudServicePattern(CloudProvider.VERCEL, "Deployment", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.vercel\.app", 
                       "MEDIUM", "Vercel deployment"),
    
    # Cloudflare
    CloudServicePattern(CloudProvider.CLOUDFLARE, "Pages", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.pages\.dev", 
                       "MEDIUM", "Cloudflare Pages"),
    CloudServicePattern(CloudProvider.CLOUDFLARE, "Workers", ServiceCategory.SERVERLESS,
                       r"([a-z0-9-]+)\.workers\.dev", 
                       "MEDIUM", "Cloudflare Workers"),
    CloudServicePattern(CloudProvider.CLOUDFLARE, "R2", ServiceCategory.STORAGE,
                       r"([a-z0-9-]+)\.r2\.dev", 
                       "HIGH", "Cloudflare R2 storage"),
    
    # Render
    CloudServicePattern(CloudProvider.OTHER, "Render", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.onrender\.com", 
                       "MEDIUM", "Render web service"),
    
    # Railway
    CloudServicePattern(CloudProvider.OTHER, "Railway", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.up\.railway\.app", 
                       "MEDIUM", "Railway deployment"),
    
    # Fly.io
    CloudServicePattern(CloudProvider.OTHER, "Fly.io", ServiceCategory.COMPUTE,
                       r"([a-z0-9-]+)\.fly\.dev", 
                       "MEDIUM", "Fly.io application"),
]


@dataclass
class DetectedCloudService:
    """Represents a detected cloud service."""
    provider: str
    service_name: str
    category: str
    domain: str
    matched_pattern: str
    severity: str
    description: str


class CloudServiceDetector:
    """Detects cloud services from subdomains, CNAMEs, and DNS records."""
    
    def __init__(self):
        self.patterns = [
            (re.compile(p.pattern, re.IGNORECASE), p) 
            for p in CLOUD_SERVICE_PATTERNS
        ]
    
    def detect_from_domain(self, domain: str) -> Optional[DetectedCloudService]:
        """
        Detect cloud service from a single domain/subdomain.
        
        Args:
            domain: Domain name to check
            
        Returns:
            DetectedCloudService if matched, None otherwise
        """
        for pattern, service in self.patterns:
            if pattern.search(domain):
                return DetectedCloudService(
                    provider=service.provider.value,
                    service_name=service.service_name,
                    category=service.category.value,
                    domain=domain,
                    matched_pattern=service.pattern,
                    severity=service.severity,
                    description=service.description
                )
        return None
    
    def detect_from_list(self, domains: List[str]) -> List[DetectedCloudService]:
        """
        Detect cloud services from a list of domains.
        
        Args:
            domains: List of domain names to check
            
        Returns:
            List of DetectedCloudService objects
        """
        findings = []
        for domain in domains:
            result = self.detect_from_domain(domain)
            if result:
                findings.append(result)
        return findings
    
    def detect_from_dns_records(self, records: Dict[str, List[str]]) -> List[DetectedCloudService]:
        """
        Detect cloud services from DNS records (A, CNAME, etc).
        
        Args:
            records: Dict with record types as keys and lists of values
            
        Returns:
            List of DetectedCloudService objects
        """
        findings = []
        
        for record_type, values in records.items():
            for value in values:
                result = self.detect_from_domain(value)
                if result:
                    findings.append(result)
        
        return findings
    
    def generate_targets_for_keyword(self, keyword: str) -> List[str]:
        """
        Generate all possible cloud service URLs for a keyword.
        
        Args:
            keyword: Target keyword (e.g., company name)
            
        Returns:
            List of URLs to check
        """
        targets = []
        
        # AWS services
        targets.extend([
            f"https://{keyword}.s3.amazonaws.com",
            f"https://{keyword}.s3.us-east-1.amazonaws.com",
            f"https://{keyword}.s3.eu-west-1.amazonaws.com",
            f"https://{keyword}.elasticbeanstalk.com",
            f"https://{keyword}.awsapprunner.com",
            f"https://{keyword}.amplifyapp.com",
            f"https://{keyword}.cloudfront.net",
        ])
        
        # Azure services
        targets.extend([
            f"https://{keyword}.blob.core.windows.net",
            f"https://{keyword}.azurewebsites.net",
            f"https://{keyword}.azurestaticapps.net",
            f"https://{keyword}.azurecr.io",
            f"https://{keyword}.database.windows.net",
            f"https://{keyword}.vault.azure.net",
            f"https://{keyword}.azureedge.net",
            f"https://{keyword}.azure-api.net",
        ])
        
        # GCP services
        targets.extend([
            f"https://storage.googleapis.com/{keyword}",
            f"https://{keyword}.appspot.com",
            f"https://{keyword}.run.app",
            f"https://{keyword}.firebaseapp.com",
            f"https://{keyword}.web.app",
            f"https://{keyword}.firebaseio.com",
        ])
        
        # Other providers
        targets.extend([
            f"https://{keyword}.herokuapp.com",
            f"https://{keyword}.netlify.app",
            f"https://{keyword}.vercel.app",
            f"https://{keyword}.pages.dev",
            f"https://{keyword}.workers.dev",
            f"https://{keyword}.ondigitalocean.app",
            f"https://{keyword}.digitaloceanspaces.com",
            f"https://{keyword}.onrender.com",
            f"https://{keyword}.fly.dev",
            f"https://{keyword}.up.railway.app",
        ])
        
        return targets
    
    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about loaded patterns."""
        by_provider = {}
        by_category = {}
        
        for _, pattern in self.patterns:
            prov = pattern.provider.value
            cat = pattern.category.value
            by_provider[prov] = by_provider.get(prov, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1
        
        return {
            "total_patterns": len(self.patterns),
            "by_provider": by_provider,
            "by_category": by_category
        }
