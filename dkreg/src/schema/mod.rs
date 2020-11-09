//! Schema definitions of the docker registry API

use serde::{Deserialize, Serialize};

/// JSON struct for a docker registry API errors
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ResponseErrors {
    errors: Vec<ResponseError>,
}

/// JSON struct for a docker registry API error
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ResponseError {
    code: String,
    message: String,
    detail: serde_json::Value,
}

/// JSON struct for a docker registry catalog
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct RegistryCatalog {
    pub repositories: Vec<String>,
}

/// JSON struct for repository tags
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct RepositoryTags {
    pub name: String,
    pub tags: Vec<String>,
}

/// JSON struct for an image blob
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct BlobSum {
    #[serde(rename = "blobSum")]
    pub blob_sum: String,
}

/// JSON struct for an image history entry
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct V1Compatibility {
    #[serde(rename = "v1Compatibility")]
    pub v1_compatibility: String,
}

#[derive(Default, Deserialize, Serialize, Debug)]
pub struct Jwk {
    pub crv: String,
    pub kid: String,
    pub kty: String,
    pub x: String,
    pub y: String,
}

#[derive(Default, Deserialize, Serialize, Debug)]
pub struct JSonWebSignature {
    pub jwk: Jwk,
    pub alg: String,
}

#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageSignature {
    pub header: JSonWebSignature,
}

/// JSON struct for an image manifest
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageManifestV1 {
    pub name: String,
    pub tag: String,
    pub architecture: String,
    #[serde(rename = "fsLayers")]
    pub fs_layers: Vec<BlobSum>,
    pub history: Option<Vec<V1Compatibility>>,
    #[serde(rename = "schemaVersion")]
    pub schema_version: i32,
    pub signatures: Option<Vec<ImageSignature>>,
}

#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageManifestConfig {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub size: i64,
    pub digest: String,
}

#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageManifestLayer {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub size: i64,
    pub digest: String,
    pub urls: Option<Vec<String>>,
}

#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageManifestV2 {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i32,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub config: ImageManifestConfig,
    pub layers: Vec<ImageManifestLayer>,
}

#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageManifestPlatform {
    pub architecture: String,
    pub os: String,
    #[serde(rename = "os.version")]
    pub os_version: Option<String>,
    #[serde(rename = "os.features")]
    pub os_features: Option<Vec<String>>,
    pub variant: Option<String>,
    pub features: Option<Vec<String>>,
}

#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageManifestEntry {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub size: i64,
    pub digest: String,
    pub platform: ImageManifestPlatform,
}

/// JSON struct for an image manifest list
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageManifestList {
    #[serde(rename = "schemaVersion")]
    pub schema_version: i32,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub manifests: Vec<ImageManifestEntry>,
}

/// Enum with the type of manifests. Not strongly typed
/// because this is meant to be used to request a specific type.
#[derive(Debug)]
pub enum ImageManifestType {
    V1,
    V2,
    List,
}

/// JSON enum with the different type of image manifests.
/// Duplicated from `ImageManifestType`, but strongly typed.
/// This is returned after requesting an image manifest.
#[derive(Deserialize, Serialize, Debug)]
pub enum ImageManifest {
    V1(ImageManifestV1),
    V2(ImageManifestV2),
    List(ImageManifestList),
}

/// JSON struct that describes an image layer.
/// Used to write a file in disk when deploying/extracting images.
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageLayer {
    /// Simple ID that represents the layer number in the chain for a given image
    pub id: i32,
    #[serde(rename = "tarPath")]
    pub tar_path: String,
    #[serde(
        default,
        rename = "extractedLayerPath",
        skip_serializing_if = "String::is_empty"
    )]
    pub extracted_layer_path: String,
}

/// JSON struct that describes the layer layout of a given image.
/// Used to write a file in disk when deploying/extracting images.
#[derive(Default, Deserialize, Serialize, Debug)]
pub struct ImageLayerLayout {
    #[serde(rename = "imageName")]
    pub image_name: String,
    /// This vector contains the full paths to the layers
    /// that comprise the image. The last entry in the vector
    /// corresponds to the base-most layer.
    pub layers: Vec<ImageLayer>,
}
