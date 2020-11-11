// Copyright (c) 2020 Rafael Alcaraz Mercado. All rights reserved.
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
// THE SOURCE CODE IS AVAILABLE UNDER THE ABOVE CHOSEN LICENSE "AS IS", WITH NO WARRANTIES.

use dkreg::schema::*;
use dkreg::*;
use structopt::StructOpt;

mod layer2guid;

#[derive(Debug, StructOpt)]
#[structopt(name = "McrCli", about = "Microsoft Container Registry CLI tool")]
/// Interact with Microsoft Container Registry through a CLI
///
/// Use environment variables DKREG_USER and DKREG_PASSWORD to authenticate with the registry when sending the requests.
/// Alternatevily, use environment variable DKREG_BEARER to authenticate (takes precedence).
enum McrCli {
    /// Lists the entire repository catalog of MCR
    #[structopt(name = "catalog")]
    Catalog {
        /// Prints the json output with pretty format
        #[structopt(short = "p", long = "pretty")]
        pretty_json: bool,
    },
    /// Lists all tags available for a given MCR repository
    #[structopt(name = "tags")]
    Tags {
        /// Supplies the repository whose tags are listed
        repository: String,
        /// Prints the json output with pretty format
        #[structopt(short = "p", long = "pretty")]
        pretty_json: bool,
    },
    /// Shows the manifest for a given repository:tag image
    #[structopt(name = "manifest")]
    Manifest {
        /// Supplies the repository whose manifest is shown
        repository: String,
        /// Supplies the tag of the repository whose manifest is shown
        reference: String,
        /// Determines the type of manifest to query (v1, v2, list)
        manifest_type: String,
        /// Prints the json output with pretty format
        #[structopt(short = "p", long = "pretty")]
        pretty_json: bool,
    },
    /// Deploy a given repository:tag image to the supplied path
    #[structopt(name = "deploy")]
    Deploy {
        /// Supplies the repository image name
        image: String,
        /// Supplies the repository image tag
        tag: String,
        /// Supplies the parent path where the image will be deployed
        destination: String,
        /// Prints the json output with pretty format
        #[structopt(short = "p", long = "pretty")]
        pretty_json: bool,
    },
    /// Extracts image layers described by the specified `ImageLayerLayout.json` file.
    /// The input file for this command is created as part of `deploy` command.
    #[structopt(name = "extract")]
    Extract {
        /// Supplies the JSON file that describes the image layer layout.
        layer_layout_file: String,
        /// Supplies the tool path used to extract the individual layers.
        expand_layer_tool: String,
    },
    /// Hashes the supplied path name (string) into a layer GUID.
    #[structopt(name = "layer2guid")]
    Layer2Guid {
        /// Supplies the path name (string) to hash into a layer GUID.
        layer_path: String,
    },
}

/// Extracts image layers using the specified expand layer tool.
/// The tool is assumed to support parameters `-in <file_path> -out <destination_path> -z`.
/// This function figures out the layers to extract based on the supplied
/// JSON file.
async fn extract_image_layers(
    layer_layout_file: &str,
    expand_layer_tool: &str,
) -> Result<(), AnyError> {
    if std::path::Path::new(expand_layer_tool).exists() == false {
        panic!(
            "Expand layer {} is not an existing file path. Aborting extract.",
            expand_layer_tool
        );
    }

    let file_path = std::path::Path::new(&layer_layout_file);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)?;

    use std::io::Read;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let mut image_layer_layout: ImageLayerLayout = serde_json::from_str(&contents)?;
    log::info!("Extracting image {}", &image_layer_layout.image_name);
    log::trace!("{}", &contents);

    let parent_path = file_path.parent().unwrap().to_str().unwrap().to_string();
    let mut parent_layer_paths = String::new();
    image_layer_layout.layers.reverse();

    for layer in &mut image_layer_layout.layers {
        layer.extracted_layer_path = format!("{}\\layer_{}", &parent_path, layer.id);
        let tar_file_path = format!("{}\\{}", &parent_path, &layer.tar_path);

        std::fs::DirBuilder::new()
            .recursive(true)
            .create(&layer.extracted_layer_path)?;

        let mut args: Vec<&str> = Vec::new();
        args.push("-in");
        args.push(&tar_file_path);
        args.push("-out");
        args.push(&layer.extracted_layer_path);
        args.push("-z");

        if layer.id != 0 {
            args.push("-parentpaths");
            args.push(&parent_layer_paths);
        }

        let output = std::process::Command::new(expand_layer_tool)
            .args(&args)
            .output()?;

        if layer.id == 0 {
            log::trace!(
                "{} -in {} -out {} -z << {:?} >>",
                expand_layer_tool,
                &tar_file_path,
                &layer.extracted_layer_path,
                output
            );
        } else {
            log::trace!(
                "{} -in {} -out {} -z -parentpaths {} << {:?} >>",
                expand_layer_tool,
                &tar_file_path,
                &layer.extracted_layer_path,
                &parent_layer_paths,
                output
            );
        }

        if layer.id == 0 {
            parent_layer_paths = format!("{}", &layer.extracted_layer_path);
        } else {
            parent_layer_paths = format!("{}|{}", &parent_layer_paths, &layer.extracted_layer_path);
        }
    }

    image_layer_layout.layers.reverse();

    use std::io::{Seek, Write};
    let layer_layout_string = serde_json::to_string_pretty(&image_layer_layout)?;
    log::info!("ImageLayout: {}", &layer_layout_string);
    file.seek(std::io::SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_fmt(format_args!("{}", &layer_layout_string))?;

    Ok(())
}

async fn run(args: &McrCli) -> Result<(), AnyError> {
    macro_rules! printjson {
        ($obj:ident, $pretty:expr) => {
            if $pretty {
                println!("{}", serde_json::to_string_pretty(&$obj)?);
            } else {
                println!("{}", serde_json::to_string(&$obj)?);
            }
        };
    }

    let mcr = RegistryClient::new("https://mcr.microsoft.com");

    match args {
        McrCli::Catalog { pretty_json } => {
            let catalog = mcr.catalog().await?;
            printjson!(catalog, *pretty_json);
            Ok(())
        }
        McrCli::Tags {
            repository,
            pretty_json,
        } => {
            let tags = mcr.repository_tags(&repository).await?;
            printjson!(tags, *pretty_json);
            Ok(())
        }
        McrCli::Manifest {
            repository,
            reference,
            manifest_type,
            pretty_json,
        } => {
            let manifest_type = match manifest_type.as_ref() {
                "v1" => ImageManifestType::V1,
                "v2" => ImageManifestType::V2,
                "list" => ImageManifestType::List,
                _ => panic!(
                    "Wrong manifest type supplied: {} - Expected v1, v2 or list",
                    &manifest_type
                ),
            };

            let man = mcr
                .image_manifest(&repository, &reference, manifest_type)
                .await?;
            printjson!(man, *pretty_json);
            Ok(())
        }
        McrCli::Deploy {
            image,
            tag,
            destination,
            pretty_json,
        } => {
            let layout = mcr.pull_image(&image, &tag, &destination).await?;
            printjson!(layout, *pretty_json);
            Ok(())
        }
        McrCli::Extract {
            layer_layout_file,
            expand_layer_tool,
        } => extract_image_layers(&layer_layout_file, &expand_layer_tool).await,
        McrCli::Layer2Guid { layer_path } => {
            println!(
                "{}",
                &layer2guid::guid_to_string(layer2guid::layer_path_to_guid(&layer_path))
            );
            Ok(())
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    if let Err(e) = run(&McrCli::from_args()).await {
        println!("Failure captured running MCR CLI << {} >>", e);
        std::process::exit(-1);
    }
}
