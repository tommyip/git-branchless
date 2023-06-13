use tracing::instrument;

use super::{repo::Result, Repo, RepoError};

/// Get commit signer configured from CLI arguments and repository configurations.
#[instrument]
pub fn get_signer(
    repo: &Repo,
    gpg_sign: &Option<String>,
    no_gpg_sign: bool,
) -> Result<Option<Box<dyn git2_ext::ops::Sign>>> {
    if no_gpg_sign {
        return Ok(None);
    }
    let config = repo.inner.config().map_err(RepoError::ReadConfig)?;
    if !config
        .get_bool("commit.gpgsign")
        .map_err(RepoError::ReadConfig)?
    {
        return Ok(None);
    }
    let signer = match gpg_sign.as_deref() {
        Some("") | None => {
            let signer = git2_ext::ops::UserSign::from_config(&repo.inner, &config)
                .map_err(RepoError::ReadConfig)?;
            Box::new(signer) as Box<dyn git2_ext::ops::Sign>
        }
        Some(keyid) => {
            let format = config
                .get_string("gpg.format")
                .unwrap_or_else(|_| "openpgp".to_owned());
            match format.as_str() {
                "openpgp" => {
                    let program = config
                        .get_string("gpg.openpgp.program")
                        .or_else(|_| config.get_string("gpg.program"))
                        .unwrap_or_else(|_| "gpg".to_owned());

                    Box::new(git2_ext::ops::GpgSign::new(program, keyid.to_string()))
                        as Box<dyn git2_ext::ops::Sign>
                }
                "x509" => {
                    let program = config
                        .get_string("gpg.x509.program")
                        .unwrap_or_else(|_| "gpgsm".to_owned());

                    Box::new(git2_ext::ops::GpgSign::new(program, keyid.to_string()))
                        as Box<dyn git2_ext::ops::Sign>
                }
                "ssh" => {
                    let program = config
                        .get_string("gpg.ssh.program")
                        .unwrap_or_else(|_| "ssh-keygen".to_owned());

                    Box::new(git2_ext::ops::SshSign::new(program, keyid.to_string()))
                        as Box<dyn git2_ext::ops::Sign>
                }
                format => {
                    return Err(RepoError::ReadConfig(git2::Error::new(
                        git2::ErrorCode::Invalid,
                        git2::ErrorClass::Config,
                        format!("invalid value for gpg.format: {}", format),
                    )))
                }
            }
        }
    };
    Ok(Some(signer))
}
