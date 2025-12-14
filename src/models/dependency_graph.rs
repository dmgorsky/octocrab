use serde::{Deserialize, Serialize};

/// A diff of the dependencies between two commits
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DependencyGraphDiff {
    pub change_type: ChangeType,
    pub manifest: String,
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub package_url: Option<String>,
    pub license: Option<String>,
    pub source_repository_url: Option<String>,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scope: Scope,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ChangeType {
    #[serde(rename = "added")]
    Added,
    #[serde(rename = "removed")]
    Removed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Vulnerability {
    pub severity: String,
    pub advisory_ghsa_id: String,
    pub advisory_summary: String,
    pub advisory_url: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Scope {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "runtime")]
    Runtime,
    #[serde(rename = "development")]
    Development,
}

/// a snapshot of dependencies for a repository
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DependenciesGraphSnapshot {
    pub id: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub result: String,
    pub message: String,
}

/// a software bill of materials (SBOM) for a repository
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DependencyGraphSbom {
    pub sbom: Sbom,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Sbom {
    #[serde(rename = "SPDXID")]
    pub spdsxid: String,
    #[serde(rename = "spdxVersion")]
    pub spdx_version: String,
    pub comment: Option<String>,
    #[serde(rename = "creationInfo")]
    pub creation_info: CreationInfo,
    pub name: String,
    #[serde(rename = "dataLicense")]
    pub data_license: String,
    #[serde(rename = "documentNamespace")]
    pub document_namespace: String,
    pub packages: Vec<Package>,
    pub relationships: Option<Vec<Relationship>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Package {
    #[serde(rename = "SPDXID")]
    pub spdsxid: String,
    pub name: String,
    #[serde(rename = "versionInfo")]
    pub version_info: String,
    #[serde(rename = "downloadLocation")]
    pub download_location: String,
    #[serde(rename = "filesAnalyzed")]
    pub files_analyzed: bool,
    #[serde(rename = "licenseConcluded")]
    pub license_concluded: Option<String>,
    #[serde(rename = "licenseDeclared")]
    pub license_declared: Option<String>,
    pub supplier: Option<String>,
    #[serde(rename = "copyrightText")]
    pub copyright_text: Option<String>,
    #[serde(rename = "externalRefs")]
    pub external_refs: Option<Vec<ExternalRef>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CreationInfo {
    pub created: chrono::DateTime<chrono::Utc>,
    pub creators: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExternalRef {
    #[serde(rename = "referenceCategory")]
    pub reference_category: String,
    #[serde(rename = "referenceLocator")]
    pub reference_locator: String,
    #[serde(rename = "referenceType")]
    pub reference_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Relationship {
    #[serde(rename = "relationshipType")]
    pub relationship_type: String,
    #[serde(rename = "spdxElementId")]
    pub spdx_element_id: String,
    #[serde(rename = "relatedSpdxElement")]
    pub related_spdx_element: String,
}
