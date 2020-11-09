use dkreg::schema::*;
use dkreg::*;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "DkregCli", about = "Docker Registry CLI tool")]
/// Interact with a Docker Registry through a CLI
///
/// Use environment variables DKREG_USER and DKREG_PASSWORD to authenticate with the registry when sending the requests.
/// Alternatevily, use environment variable DKREG_BEARER to authenticate (takes precedence).
enum DkregCli {
    /// Lists the entire repository catalog of a container registry
    #[structopt(name = "catalog")]
    Catalog {
        /// Supplies the container registry address
        registry: String,
        /// Prints the json output with pretty format
        #[structopt(short = "p", long = "pretty")]
        pretty_json: bool,
    },
    /// Lists all tags available for a given repository
    #[structopt(name = "tags")]
    Tags {
        /// Supplies the registry\repository
        repository: String,
        /// Prints the json output with pretty format
        #[structopt(short = "p", long = "pretty")]
        pretty_json: bool,
    },
    /// Shows the manifest for a given registry\repository:tag image
    #[structopt(name = "manifest")]
    Manifest {
        /// Supplies the tagged repository
        tagged_repository: String,
        /// Determines the type of manifest to query (v1, v2, list)
        manifest_type: String,
        /// Prints the json output with pretty format
        #[structopt(short = "p", long = "pretty")]
        pretty_json: bool,
    },
    /// Deploy a given repository:tag image to the supplied path
    #[structopt(name = "deploy")]
    Deploy {
        /// Supplies the tagged repository
        tagged_repository: String,
        /// Supplies the parent path where the image will be deployed
        destination: String,
        /// Prints the json output with pretty format
        #[structopt(short = "p", long = "pretty")]
        pretty_json: bool,
    },
}

async fn run(args: &DkregCli) -> Result<(), AnyError> {
    macro_rules! printjson {
        ($obj:ident, $pretty:expr) => {
            if $pretty {
                println!("{}", serde_json::to_string_pretty(&$obj)?);
            } else {
                println!("{}", serde_json::to_string(&$obj)?);
            }
        };
    }

    match args {
        DkregCli::Catalog {
            registry,
            pretty_json,
        } => {
            let dkreg = RegistryClient::new(&registry);
            let catalog = dkreg.catalog().await?;
            printjson!(catalog, *pretty_json);
            Ok(())
        }
        DkregCli::Tags {
            repository,
            pretty_json,
        } => {
            let registry_repository: RegistryRepository = repository.parse()?;
            let dkreg = RegistryClient::new(&registry_repository.registry);
            let tags = dkreg
                .repository_tags(&registry_repository.repository)
                .await?;
            printjson!(tags, *pretty_json);
            Ok(())
        }
        DkregCli::Manifest {
            tagged_repository,
            manifest_type,
            pretty_json,
        } => {
            let registry_tagged_repository: RegistryTaggedRepository = tagged_repository.parse()?;
            let dkreg = RegistryClient::new(&registry_tagged_repository.registry);

            let manifest_type = match manifest_type.as_ref() {
                "v1" => ImageManifestType::V1,
                "v2" => ImageManifestType::V2,
                "list" => ImageManifestType::List,
                _ => panic!(
                    "Wrong manifest type supplied: {} - Expected v1, v2 or list",
                    &manifest_type
                ),
            };

            let man = dkreg
                .image_manifest(
                    &registry_tagged_repository.repository,
                    &registry_tagged_repository.tag,
                    manifest_type,
                )
                .await?;

            printjson!(man, *pretty_json);
            Ok(())
        }
        DkregCli::Deploy {
            tagged_repository,
            destination,
            pretty_json,
        } => {
            let registry_tagged_repository: RegistryTaggedRepository = tagged_repository.parse()?;
            let dkreg = RegistryClient::new(&registry_tagged_repository.registry);
            let layout = dkreg
                .pull_image(
                    &registry_tagged_repository.repository,
                    &registry_tagged_repository.tag,
                    &destination,
                )
                .await?;

            printjson!(layout, *pretty_json);
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    if let Err(e) = run(&DkregCli::from_args()).await {
        println!("Failure captured running DKREG CLI << {} >>", e);
        std::process::exit(-1);
    }
}
