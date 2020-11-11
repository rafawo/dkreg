// Copyright (c) 2020 Rafael Alcaraz Mercado. All rights reserved.
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
// THE SOURCE CODE IS AVAILABLE UNDER THE ABOVE CHOSEN LICENSE "AS IS", WITH NO WARRANTIES.

//! dkreg crate defines serde compatible structs of the docker registry API
//! and provides a collection of convenience abstractions to interact with the
//! API. All of it is syncrhonous, so requesting something from a docker registry
//! is blocking for the caller.

pub mod schema;

use recap::Recap;
use schema::*;

/// Alias type definition for any kind of error
pub type AnyError = std::boxed::Box<dyn std::error::Error>;

#[derive(Debug)]
pub enum ClientError {
    BlobIsNotValid {
        repository: String,
        tag: String,
        digest: String,
    },
    DockerRegistryError {
        response_error: DockerRegistryApiError,
    },
}

impl std::error::Error for ClientError {}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            ClientError::BlobIsNotValid {
                repository,
                tag,
                digest,
            } => write!(
                f,
                "Image {}:{} blob {} is not valid",
                &repository, &tag, &digest
            ),
            ClientError::DockerRegistryError { response_error } => {
                let error_text = match response_error {
                    DockerRegistryApiError::RawText(text) => text.to_owned(),
                    DockerRegistryApiError::ApiError(error) => {
                        serde_json::to_string(error).unwrap()
                    }
                };
                write!(f, "Docker Registry API error: {}", error_text)
            }
        }
    }
}

#[derive(Debug)]
pub enum DockerRegistryApiError {
    RawText(String),
    ApiError(ResponseErrors),
}

pub async fn get_docker_registry_api_error(
    response: reqwest::Response,
) -> std::boxed::Box<ClientError> {
    assert!(!response.status().is_success());
    let raw_text = response.text().await.unwrap();
    let error = match serde_json::from_str(&raw_text) {
        Ok(error_json) => ClientError::DockerRegistryError {
            response_error: DockerRegistryApiError::ApiError(error_json),
        },
        Err(_) => ClientError::DockerRegistryError {
            response_error: DockerRegistryApiError::RawText(raw_text),
        },
    };

    std::boxed::Box::new(error)
}

/// Struct with typely safe definition of an image from a specific docker registry repository.
#[derive(Debug, serde::Deserialize, Recap, PartialEq)]
#[recap(regex = r#"(?P<registry>http?s://[^/\\]+)(/|\\)(?P<repository>.+)"#)]
pub struct RegistryRepository {
    pub registry: String,
    pub repository: String,
}

/// Struct with typely safe definition of a tagged image from a specific docker registry repository.
#[derive(Debug, serde::Deserialize, Recap, PartialEq)]
#[recap(regex = r#"(?P<registry>http?s://[^/\\]+)(/|\\)(?P<repository>.+):(?P<tag>.+)"#)]
pub struct RegistryTaggedRepository {
    pub registry: String,
    pub repository: String,
    pub tag: String,
}

/// Microsoft Container Registry endpoint client
#[derive(Debug)]
pub struct RegistryClient {
    endpoint: String,
    client: reqwest::Client,
    user: Option<String>,
    password: Option<String>,
    bearer: Option<String>,
}

impl RegistryClient {
    /// Creates a new docker registry client.
    /// If DKREG_BEARER environment variable is set, this will cache the value
    /// internally for user authentication when calling the REST API.
    /// If DKREG_USER and DKREG_PASSWORD environment variables are set,
    /// this will cache the values internally for user authentication
    /// when calling the REST API.
    /// DKREG_BEARER has precedence over DKREG_USER, DKREG_PASSWORD.
    pub fn new(registry: &str) -> RegistryClient {
        RegistryClient {
            endpoint: registry.to_string(),
            client: reqwest::Client::builder().build().unwrap(),
            user: std::env::var("DKREG_USER").ok(),
            password: std::env::var("DKREG_PASSWORD").ok(),
            bearer: std::env::var("DKREG_BEARER").ok(),
        }
    }

    /// Creates a new docker registry client with basic authentication to the REST API.
    pub fn new_with_basic_auth(registry: &str, user: &str, password: &str) -> RegistryClient {
        RegistryClient {
            endpoint: registry.to_string(),
            client: reqwest::Client::builder().build().unwrap(),
            user: Some(user.to_string()),
            password: Some(password.to_string()),
            bearer: None,
        }
    }

    /// Creates a new docker registry client with bearer authentication to the REST API.
    pub fn new_with_bearer_auth(registry: &str, bearer: &str) -> RegistryClient {
        RegistryClient {
            endpoint: registry.to_string(),
            client: reqwest::Client::builder().build().unwrap(),
            user: None,
            password: None,
            bearer: Some(bearer.to_string()),
        }
    }

    /// Creates a new docker registry client with the supplied client for HTTP requests.
    pub fn new_with_client(registry: &str, client: reqwest::Client) -> RegistryClient {
        RegistryClient {
            endpoint: registry.to_string(),
            client,
            user: None,
            password: None,
            bearer: None,
        }
    }

    /// Adds authentication to request builder.
    fn add_builder_auth(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(bearer) = self.bearer.as_ref() {
            log::debug!("Using bearer authentication");
            builder.bearer_auth(bearer)
        } else if let (Some(user), Some(password)) = (self.user.as_ref(), self.password.as_ref()) {
            log::debug!("Using basic authentication");
            builder.basic_auth(user, Some(password))
        } else {
            builder
        }
    }

    /// Returns whether this docker registry client has authentication enabled.
    pub fn has_auth(&self) -> bool {
        (self.user.is_some() && self.password.is_some()) || self.bearer.is_some()
    }

    /// Sends a REST API GET request for a docker registry and returns the reqwest response.
    pub async fn get_response(&self, request: &str) -> Result<reqwest::Response, AnyError> {
        let mut builder = self.client.get(request);
        builder = self.add_builder_auth(builder);
        let response = builder.send().await?;
        log::trace!("Request:{} Response:{:?}", request, response);
        if !response.status().is_success() {
            return Err(get_docker_registry_api_error(response).await);
        }

        Ok(response)
    }

    /// Sends a REST API GET request for a docker registry and returns the response's body text.
    pub async fn get_text(&self, request: &str) -> Result<String, AnyError> {
        let response = self.get_response(request).await?;
        Ok(response.text().await?)
    }

    /// Templated method that sends a REST API GET request for a docker registry
    /// and returns a deserialized JSON struct representation
    /// of the response's body text.
    pub async fn get<'a, T>(&self, request: &str) -> Result<T, AnyError>
    where
        for<'de> T: serde::Deserialize<'de> + 'a,
    {
        let response = self.get_response(request).await?;
        let raw_data = response.text().await?;
        log::trace!("Request:{} RawData:{}", request, &raw_data);
        let data: T = serde_json::from_str(&raw_data)?;
        Ok(data)
    }

    /// Returns the docker registry repository catalog.
    pub async fn catalog(&self) -> Result<RegistryCatalog, AnyError> {
        let request = format!("{}/v2/_catalog", &self.endpoint);
        Ok(self.get::<RegistryCatalog>(&request).await?)
    }

    /// Returns all the tags available for a docker registry repository.
    pub async fn repository_tags(&self, name: &str) -> Result<RepositoryTags, AnyError> {
        let request = format!("{}/v2/{}/tags/list", &self.endpoint, name);
        Ok(self.get::<RepositoryTags>(&request).await?)
    }

    /// Returns a docker registry repository image manfiest with the specified schema type.
    pub async fn image_manifest(
        &self,
        name: &str,
        reference: &str,
        manifest_type: ImageManifestType,
    ) -> Result<ImageManifest, AnyError> {
        let request = format!("{}/v2/{}/manifests/{}", self.endpoint, name, reference);
        let mut builder = self.client.get(&request);
        builder = self.add_builder_auth(builder);
        builder = match manifest_type {
            ImageManifestType::V1 => builder.header(
                "Accept",
                "application/vnd.docker.distribution.manifest.v1+json",
            ),
            ImageManifestType::V2 => builder.header(
                "Accept",
                "application/vnd.docker.distribution.manifest.v2+json",
            ),
            ImageManifestType::List => builder.header(
                "Accept",
                "application/vnd.docker.distribution.manifest.list.v2+json",
            ),
        };

        let response = builder.send().await?;
        log::trace!(
            "Request:{} ManifestType:{:?} Response:{:?}",
            &request,
            manifest_type,
            response
        );
        if !response.status().is_success() {
            return Err(get_docker_registry_api_error(response).await);
        }

        let content_type = match response.headers().get("Content-Type") {
            Some(content_type) => match content_type.to_str() {
                Ok(content_type) => Some(String::from(content_type)),
                Err(_) => None,
            },
            None => None,
        };

        let raw_data = response.text().await?;
        log::trace!("Request:{} RawData:{}", &request, &raw_data);

        let parse_by_manifest_type =
            |raw_data: &str, manifest_type: ImageManifestType| -> Result<ImageManifest, AnyError> {
                match manifest_type {
                    ImageManifestType::V1 => {
                        let man: ImageManifestV1 = serde_json::from_str(raw_data)?;
                        Ok(ImageManifest::V1(man))
                    }
                    ImageManifestType::V2 => {
                        let man: ImageManifestV2 = serde_json::from_str(raw_data)?;
                        Ok(ImageManifest::V2(man))
                    }
                    ImageManifestType::List => {
                        let man: ImageManifestList = serde_json::from_str(raw_data)?;
                        Ok(ImageManifest::List(man))
                    }
                }
            };

        let manifest = match content_type {
            Some(content_type) => match content_type.as_str() {
                "application/vnd.docker.distribution.manifest.v1+json" => {
                    let man: ImageManifestV1 = serde_json::from_str(&raw_data)?;
                    ImageManifest::V1(man)
                }
                "application/vnd.docker.distribution.manifest.v1+prettyjws" => {
                    let man: ImageManifestV1 = serde_json::from_str(&raw_data)?;
                    ImageManifest::V1(man)
                }
                "application/vnd.docker.distribution.manifest.v2+json" => {
                    let man: ImageManifestV2 = serde_json::from_str(&raw_data)?;
                    ImageManifest::V2(man)
                }
                "application/vnd.docker.distribution.manifest.list.v2+json" => {
                    let man: ImageManifestList = serde_json::from_str(&raw_data)?;
                    ImageManifest::List(man)
                }
                _ => parse_by_manifest_type(&raw_data, manifest_type)?,
            },
            None => parse_by_manifest_type(&raw_data, manifest_type)?,
        };

        Ok(manifest)
    }

    /// Returns whether a fs layer blob exists for the given image and digest.
    pub async fn blob_exists(&self, name: &str, digest: &str) -> Result<bool, AnyError> {
        let request = format!("{}/v2/{}/blobs/{}", &self.endpoint, name, digest);
        let mut builder = self.client.head(&request);
        builder = self.add_builder_auth(builder);
        let response = builder.send().await?;
        log::trace!("BlobExists -- Request:{} Response:{:?}", &request, response);
        Ok(response.status().is_success())
    }

    /// Pulls an image:tag to the supplied destination folder.
    /// The layers are written as .gz files, with the layer ID number from high to low.
    /// Because the last entry in the layers vector corresponds to the base layer, its ID
    /// will be 0, and the first entry in the vector is the layer ID vector size - 1.
    pub async fn pull_image(
        &self,
        image: &str,
        tag: &str,
        destination_folder: &str,
    ) -> Result<ImageLayerLayout, AnyError> {
        std::fs::DirBuilder::new()
            .recursive(true)
            .create(destination_folder)?;

        log::info!(
            "deploying image {}:{} to {}",
            &image,
            &tag,
            &destination_folder
        );

        // Prefer to use the v2 schema manifest since it contains urls
        // to possible foreign layers.
        let manifest = match self.image_manifest(image, tag, ImageManifestType::V2).await {
            Ok(manifest) => match manifest {
                ImageManifest::V2(manifest) => {
                    log::debug!("Image {}:{} found with V2 manifest", image, tag);
                    manifest
                }
                _ => panic!("Got wrong manifest type requesting V2: {:?}", manifest),
            },
            Err(_) => {
                // An error trying to get a V2 image manifest possibly means
                // that the tag refers to a multi-arch manifest.
                // Look through the list of manifests for an image that matches
                // the host's architecture
                log::debug!("Image {}:{} might be of list manifest", image, tag);

                if let ImageManifest::List(manifest_list) = self
                    .image_manifest(image, tag, ImageManifestType::List)
                    .await?
                {
                    let host_arch = match std::env::var("PROCESSOR_ARCHITECTURE") {
                        Ok(host_arch) => {
                            log::debug!("Host architecture {}", host_arch);
                            host_arch.to_lowercase()
                        }
                        Err(_) => {
                            log::debug!(
                                "Host architecture not found in env var, defaulting to AMD64"
                            );
                            "amd64".to_string()
                        }
                    };

                    log::trace!(
                        "Image {}:{} found with list manifest: {}",
                        image,
                        tag,
                        &serde_json::to_string(&manifest_list)?
                    );

                    let mut v2_manifest: Option<ImageManifestV2> = None;
                    for manifest in manifest_list.manifests {
                        let manifest_arch = manifest.platform.architecture.to_lowercase();
                        if manifest_arch == host_arch {
                            log::trace!(
                                "Found matching manifest with host architecture: {}",
                                &serde_json::to_string(&manifest)?
                            );

                            let manifest = self
                                .image_manifest(image, &manifest.digest, ImageManifestType::V2)
                                .await?;
                            v2_manifest = match manifest {
                                ImageManifest::V2(manifest) => {
                                    log::debug!("Image {}:{} found with V2 manifest", image, tag);
                                    Some(manifest)
                                }
                                _ => {
                                    panic!("Got wrong manifest type requesting V2: {:?}", manifest)
                                }
                            }
                        }
                    }

                    v2_manifest.unwrap()
                } else {
                    panic!("Got wrong manifest type requesting List");
                }
            }
        };

        log::trace!(
            "Image {}:{} manifest: {}",
            image,
            tag,
            &serde_json::to_string(&manifest)?
        );

        let mut layer_layout = ImageLayerLayout {
            image_name: format!("{}:{}", image, tag),
            layers: Vec::new(),
        };
        let mut layer_id = 0;

        for layer in manifest.layers {
            let layer_file_name = format!("layer_{}.tar.gz", layer_id);
            let layer_destination_path = std::path::Path::new(destination_folder)
                .join(std::path::Path::new(&layer_file_name));
            let mut layer_file = std::fs::File::create(layer_destination_path)?;
            log::info!(
                "Created target file {} for blob {}",
                &layer_file_name,
                &layer.digest
            );

            if self.blob_exists(image, &layer.digest).await? {
                let request = format!("{}/v2/{}/blobs/{}", &self.endpoint, image, &layer.digest);
                let response = self.get_response(&request).await?;
                log::trace!("Request:{} Response:{:?}", &request, response);
                let bytes = response.bytes().await?.to_vec();
                std::io::copy(&mut bytes.as_slice(), &mut layer_file)?;
            } else {
                // If a blob is thought to be non-existent, it's likely
                // this is a foreign layer and needs to be downloaded from
                // another url.
                let error = std::boxed::Box::new(ClientError::BlobIsNotValid {
                    repository: image.to_string(),
                    tag: tag.to_string(),
                    digest: layer.digest.clone(),
                });

                log::debug!(
                    "Blob {} not found, searching in foreign layers",
                    &layer.digest
                );

                match layer.urls {
                    Some(urls) => {
                        let mut found_layer = false;

                        for url in urls {
                            log::debug!(
                                "Searching blob {} in foreign layer {}",
                                &layer.digest,
                                &url
                            );
                            if let Ok(response) = self.get_response(&url).await {
                                let bytes = response.bytes().await?.to_vec();
                                if let Ok(_) = std::io::copy(&mut bytes.as_slice(), &mut layer_file)
                                {
                                    // If the response succeeds and the file
                                    // copy completes, it's not necessary to try
                                    // with any other url.
                                    log::info!(
                                        "Found blob {} in foreign layer {}",
                                        &layer.digest,
                                        &url
                                    );
                                    found_layer = true;
                                    break;
                                }
                            }
                        }

                        // If none of the supplied urls succeeded to deploy the layer,
                        // we return an error.
                        if found_layer == false {
                            return Err(error);
                        }
                    }
                    None => {
                        return Err(error);
                    }
                }
            }

            log::info!(
                "Copied contents of blob {} to file {}",
                &layer.digest,
                &layer_file_name
            );

            layer_layout.layers.push(ImageLayer {
                id: layer_id,
                tar_path: layer_file_name,
                extracted_layer_path: String::new(),
            });

            layer_id += 1;
        }

        layer_layout.layers.reverse();
        let layer_layout_destination_path = std::path::Path::new(destination_folder)
            .join(std::path::Path::new("ImageLayerLayout.json"));
        let mut file = std::fs::File::create(layer_layout_destination_path)?;

        use std::io::Write;
        let layer_layout_string = serde_json::to_string_pretty(&layer_layout)?;
        log::info!("ImageLayout: {}", &layer_layout_string);
        file.write_fmt(format_args!("{}", &layer_layout_string))?;

        Ok(layer_layout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_image() {
        let repoimg: RegistryRepository = "https://mcr.microsoft.com/windows/nanoserver"
            .parse()
            .unwrap();
        assert_eq!(
            &RegistryRepository {
                registry: String::from("https://mcr.microsoft.com"),
                repository: String::from("windows/nanoserver"),
            },
            &repoimg
        )
    }

    #[test]
    fn repository_image_dk_ubuntu() {
        let repoimg: RegistryRepository = "https://registry-1.docker.io/library/ubuntu"
            .parse()
            .unwrap();
        assert_eq!(
            &RegistryRepository {
                registry: String::from("https://registry-1.docker.io"),
                repository: String::from("library/ubuntu"),
            },
            &repoimg
        )
    }

    #[test]
    fn repository_image_dk_ubuntu_fwdslash() {
        let repoimg: RegistryRepository = "https://registry-1.docker.io\\library\\ubuntu"
            .parse()
            .unwrap();
        assert_eq!(
            &RegistryRepository {
                registry: String::from("https://registry-1.docker.io"),
                repository: String::from("library\\ubuntu"),
            },
            &repoimg
        )
    }

    #[test]
    fn repository_image_fwdslash() {
        let repoimg: RegistryRepository = "https://mcr.microsoft.com\\windows\\nanoserver"
            .parse()
            .unwrap();
        assert_eq!(
            &RegistryRepository {
                registry: String::from("https://mcr.microsoft.com"),
                repository: String::from("windows\\nanoserver"),
            },
            &repoimg
        )
    }

    #[test]
    fn repository_tagged_image() {
        let repotagimg: RegistryTaggedRepository =
            "https://mcr.microsoft.com/windows/nanoserver:1803"
                .parse()
                .unwrap();
        assert_eq!(
            &RegistryTaggedRepository {
                registry: String::from("https://mcr.microsoft.com"),
                repository: String::from("windows/nanoserver"),
                tag: String::from("1803"),
            },
            &repotagimg
        )
    }

    #[test]
    fn repository_tagged_image_fwdslash() {
        let repotagimg: RegistryTaggedRepository =
            "https://mcr.microsoft.com\\windows\\nanoserver:1803"
                .parse()
                .unwrap();
        assert_eq!(
            &RegistryTaggedRepository {
                registry: String::from("https://mcr.microsoft.com"),
                repository: String::from("windows\\nanoserver"),
                tag: String::from("1803"),
            },
            &repotagimg
        )
    }
}
