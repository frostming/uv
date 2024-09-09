use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use distribution_filename::{DistFilename, SourceDistExtension, SourceDistFilename};
use fs_err::File;
use futures::TryStreamExt;
use glob::{glob, GlobError, PatternError};
use itertools::Itertools;
use python_pkginfo::Metadata;
use reqwest::header::AUTHORIZATION;
use reqwest::multipart::Part;
use reqwest::{Body, StatusCode};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::{fmt, io};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tracing::{debug, enabled, trace, Level};
use url::Url;
use uv_client::BaseClient;
use uv_fs::Simplified;
use uv_metadata::read_metadata_async_seek;

#[derive(Error, Debug)]
pub enum PublishError {
    #[error("Invalid publish paths")]
    Pattern(#[from] PatternError),
    /// [`GlobError`] is a wrapped io error.
    #[error(transparent)]
    Glob(#[from] GlobError),
    #[error("Path patterns didn't match any wheels or source distributions")]
    NoFiles,
    #[error(transparent)]
    Fmt(#[from] fmt::Error),
    #[error("Failed to publish: `{}`", _0.user_display())]
    PublishFile(PathBuf, #[source] PublishFileError),
}

/// Failed to publish a specific file.
///
/// Proxy over [`PublishError`] to attach the path to the error message.
#[derive(Error, Debug)]
pub enum PublishFileError {
    #[error(transparent)]
    PkgInfoError(#[from] python_pkginfo::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("Failed to read metadata")]
    Metadata(#[from] uv_metadata::Error),
    #[error("Failed to send POST request: `{0}`")]
    ReqwestMiddleware(Url, #[source] reqwest_middleware::Error),
    #[error("Only files ending in `.tar.gz` are valid source distributions: `{0}`")]
    InvalidExtension(SourceDistFilename),
    #[error("No PKG-INFO file found")]
    MissingPkgInfo,
    #[error("Multiple PKG-INFO files found: `{0}`")]
    MultiplePkgInfo(String),
    #[error("Failed to read: `{0}`")]
    Read(String, #[source] io::Error),
    #[error("Upload failed with status {0} and no body")]
    StatusNoBody(StatusCode, #[source] reqwest::Error),
    #[error("Upload failed with status code {0}: {1}")]
    Status(StatusCode, String),
    /// The registry returned a "403 Forbidden"
    #[error("Username or password are incorrect (status code {0}): {1}")]
    AuthenticationError(StatusCode, String),
}

pub fn files_for_publishing(
    paths: Option<Vec<String>>,
) -> Result<Vec<(PathBuf, DistFilename)>, PublishError> {
    let paths = paths.unwrap_or_else(|| vec!["dist/*".to_string()]);
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for path in paths {
        for entry in glob(&path)? {
            let entry = entry?;
            if !seen.insert(entry.clone()) {
                continue;
            }
            if let Some(dist_filename) = entry
                .file_name()
                .and_then(|filename| filename.to_str())
                .and_then(DistFilename::try_from_normalized_filename)
            {
                files.push((entry, dist_filename));
            }
        }
    }
    Ok(files)
}

/// Calculate the SHA256 of a file.
fn hash_file(path: impl AsRef<Path>) -> Result<String, io::Error> {
    let mut file = File::open(path.as_ref())?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
}

// Not in `uv-metadata` because we only support tar files here.
async fn source_dist_pkg_info(file: &Path) -> Result<Vec<u8>, PublishFileError> {
    let file = fs_err::tokio::File::open(&file).await?;
    let reader = tokio::io::BufReader::new(file);
    let decoded = async_compression::tokio::bufread::GzipDecoder::new(reader);
    let mut archive = tokio_tar::Archive::new(decoded);
    let mut pkg_infos: Vec<(PathBuf, Vec<u8>)> = archive
        .entries()?
        .map_err(|err| PublishFileError::from(err))
        .try_filter_map(|mut entry| async move {
            let path = entry
                .path()
                .map_err(|err| PublishFileError::from(err))?
                .to_path_buf();
            let mut components = path.components();
            let Some(_top_level) = components.next() else {
                return Ok(None);
            };
            let Some(pkg_info) = components.next() else {
                return Ok(None);
            };
            if components.next().is_some() || pkg_info.as_os_str() != "PKG-INFO" {
                return Ok(None);
            }
            let mut buffer = Vec::new();
            entry
                .read_to_end(&mut buffer)
                .await
                .map_err(|err| PublishFileError::Read(path.to_string_lossy().to_string(), err))?;
            Ok(Some((path, buffer)))
        })
        .try_collect()
        .await?;
    match pkg_infos.len() {
        0 => Err(PublishFileError::MissingPkgInfo),
        1 => Ok(pkg_infos.remove(0).1),
        _ => Err(PublishFileError::MultiplePkgInfo(
            pkg_infos
                .iter()
                .map(|(path, _buffer)| path.to_string_lossy())
                .join(", "),
        )),
    }
}

async fn metadata(file: &Path, filename: &DistFilename) -> Result<Metadata, PublishFileError> {
    let contents = match filename {
        DistFilename::SourceDistFilename(source_dist) => {
            if source_dist.extension != SourceDistExtension::TarGz {
                // See PEP 625. While we support installing legacy source distributions, we don't
                // support creating and uploading them.
                return Err(PublishFileError::InvalidExtension(source_dist.clone()));
            }
            source_dist_pkg_info(file).await?
        }
        DistFilename::WheelFilename(wheel) => {
            let file = fs_err::tokio::File::open(&file).await?;
            let reader = tokio::io::BufReader::new(file);
            read_metadata_async_seek(wheel, reader).await?
        }
    };
    Ok(Metadata::parse(&contents)?)
}

/// Upload a file to a registry.
///
/// Returns `true` if the file was newly uploaded and `false` if it already existed.
pub async fn upload(
    file: &Path,
    filename: &DistFilename,
    registry: &Url,
    client: &BaseClient,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<bool, PublishFileError> {
    let hash_hex = hash_file(file)?;

    let metadata = metadata(file, filename).await?;

    let mut api_metadata = vec![
        (":action", "file_upload".to_string()),
        ("sha256_digest", hash_hex),
        ("protocol_version", "1".to_string()),
        ("metadata_version", metadata.metadata_version.clone()),
        // Twine transforms the name with `re.sub("[^A-Za-z0-9.]+", "-", name)`
        // * <https://github.com/pypa/twine/issues/743>
        // * <https://github.com/pypa/twine/blob/5bf3f38ff3d8b2de47b7baa7b652c697d7a64776/twine/package.py#L57-L65>
        // warehouse seems to call `packaging.utils.canonicalize_name` nowadays and has a separate
        // `normalized_name`, so we'll start with this and we'll readjust if there are user reports.
        ("name", metadata.name.clone()),
        ("version", metadata.version.clone()),
        ("filetype", filename.filetype().to_string()),
    ];

    if let DistFilename::WheelFilename(wheel) = filename {
        api_metadata.push(("pyversion", wheel.python_tag.join(".")));
    } else {
        //api_metadata.push(("pyversion", "py3".to_string()));
    }

    let mut add_option = |name, value: Option<String>| {
        if let Some(some) = value.clone() {
            api_metadata.push((name, some));
        }
    };

    // https://github.com/pypi/warehouse/blob/d2c36d992cf9168e0518201d998b2707a3ef1e72/warehouse/forklift/legacy.py#L1376-L1430
    add_option("summary", metadata.summary);
    add_option("description", metadata.description);
    add_option(
        "description_content_type",
        metadata.description_content_type,
    );
    add_option("author", metadata.author);
    add_option("author_email", metadata.author_email);
    add_option("maintainer", metadata.maintainer);
    add_option("maintainer_email", metadata.maintainer_email);
    add_option("license", metadata.license);
    add_option("keywords", metadata.keywords);
    add_option("home_page", metadata.home_page);
    add_option("download_url", metadata.download_url);

    // GitLab PyPI repository API implementation requires this metadata field
    // and twine always includes it in the request, even when it's empty.
    api_metadata.push((
        "requires_python",
        metadata.requires_python.unwrap_or(String::new()),
    ));

    let mut add_vec = |name, values: Vec<String>| {
        for i in values {
            api_metadata.push((name, i.clone()));
        }
    };

    add_vec("classifiers", metadata.classifiers);
    add_vec("platform", metadata.platforms);
    add_vec("requires_dist", metadata.requires_dist);
    add_vec("provides_dist", metadata.provides_dist);
    add_vec("obsoletes_dist", metadata.obsoletes_dist);
    add_vec("requires_external", metadata.requires_external);
    add_vec("project_urls", metadata.project_urls);

    let mut form = reqwest::multipart::Form::new();
    for (key, value) in api_metadata {
        form = form.text(key, value);
    }

    let file: tokio::fs::File = fs_err::tokio::File::open(file).await?.into();
    let file_reader = Body::from(file);
    form = form.part(
        "content",
        Part::stream(file_reader).file_name(filename.to_string()),
    );

    let mut request = client.client().post(registry.clone()).multipart(form);
    if let (Some(username), Some(password)) = (username, password) {
        debug!("Using username/password basic auth");
        let credentials = BASE64_STANDARD.encode(format!("{username}:{password}"));
        request = request.header(AUTHORIZATION, format!("Basic {credentials}"));
    }
    let response = request
        .send()
        .await
        .map_err(|err| PublishFileError::ReqwestMiddleware(registry.clone(), err))?;
    trace!("Response headers for {} {:?}", registry, response);
    let status_code = response.status();

    if status_code.is_success() {
        if enabled!(Level::TRACE) {
            match response.text().await {
                Ok(response_content) => {
                    trace!("Response content for {}: {}", registry, response_content);
                }
                Err(err) => {
                    trace!("Failed to read response content for {}: {}", registry, err);
                }
            }
        }
        return Ok(true);
    }

    let upload_error = response
        .bytes()
        .await
        .map_err(|err| PublishFileError::StatusNoBody(status_code, err))?;
    let upload_error = String::from_utf8_lossy(&*upload_error);

    trace!(
        "Response content for non-200 for {}: {}",
        registry,
        upload_error
    );

    debug!("Upload error response: {}", upload_error);
    // Detect existing file errors the way twine does.
    // https://github.com/pypa/twine/blob/c512bbf166ac38239e58545a39155285f8747a7b/twine/commands/upload.py#L34-L72
    if status_code == 403 {
        if upload_error.contains("overwrite artifact") {
            // Artifactory (https://jfrog.com/artifactory/)
            Ok(false)
        } else {
            Err(PublishFileError::AuthenticationError(
                status_code,
                upload_error.to_string(),
            ))
        }
    } else if status_code == 409 {
        // conflict, pypiserver (https://pypi.org/project/pypiserver)
        Ok(false)
    } else if status_code == 400
        && (upload_error.contains("updating asset") || upload_error.contains("already been taken"))
    {
        // Nexus Repository OSS (https://www.sonatype.com/nexus-repository-oss)
        // and Gitlab Enterprise Edition (https://about.gitlab.com)
        Ok(false)
    } else {
        Err(PublishFileError::Status(
            status_code,
            upload_error.to_string(),
        ))
    }
}
