//! A packslip project on GitHub or GitLab is located by its name and pinned
//! by the forge's repository ID, which the signing certificate records and
//! no rename changes. A renamed repository's releases, signed under the new
//! name, keep installing under the old one; a repository that moved to
//! another owner, or a new repository that took a deleted one's name, is
//! refused. The IDs come from what mise pinned before (`packslip/pins.toml`
//! and `mise.lock`), or, the first time, from what the forge says the name
//! resolves to now.

use std::path::Path;

use eyre::{Report, eyre};
use packslip::forge::{
    self, Check, Continuity, Expected, ForgePin, IdentityError, PinSource, Transfer,
};
use packslip::sigstore::SourceRepository;
use packslip::{ForgeError, ForgeVerified, Options, Verified, VerifiedList};

use crate::config::{Settings, SettingsExt};
use crate::lockfile::PlatformInfo;
use crate::{github, gitlab, packslip_pins};

/// What a forge project's release must be signed by: the forge identities
/// mise pinned for the project, and, when it pinned none, the repository ID
/// the forge gives for the name.
#[derive(Debug, Clone)]
pub(crate) struct ForgeExpect {
    project: String,
    /// This machine's pin first, then the lockfile's. Each one must hold.
    pins: Vec<(PinSource, ForgePin)>,
    resolved: Option<String>,
    /// The ID of the requested project's owner, when the forge's answer for
    /// the name is under that owner.
    resolved_owner: Option<String>,
}

/// What the forge says a project name stands for now.
#[derive(Debug, Clone)]
struct ForgeRepository {
    id: String,
    /// The ID of the owner the project was requested under, when the forge
    /// answered under that owner's name. An answer under another owner is a
    /// redirect after a transfer, and says nothing about who owns the
    /// requested name.
    owner_id: Option<String>,
    /// The project as it is called now, `github.com/owner/repo[/tool]` or
    /// `gitlab.com/<path>`.
    project: String,
}

/// Whether `current`, a repository path the forge gave (`owner/repo`, or a
/// GitLab `group/sub/project`), is under the owner or namespace `owner`.
/// Owner names are case-insensitive on both forges.
fn under_owner(owner: &str, current: &str) -> bool {
    current
        .rsplit_once('/')
        .is_some_and(|(namespace, _)| namespace.eq_ignore_ascii_case(owner))
}

/// The repository ID and name the forge gives `project` now, following a
/// rename's redirect. None offline, for a name that is not a forge project,
/// or when the forge cannot be asked (rate limit, no network): the check then
/// falls back to the name, which is what mise did before it had IDs.
async fn lookup(project: &str) -> Option<ForgeRepository> {
    if Settings::get().offline() {
        return None;
    }
    if let Some((host, owner, repo)) = packslip::model::repository(project) {
        let subpath = packslip::model::repository_subpath(project)
            .map(|sub| format!("/{sub}"))
            .unwrap_or_default();
        return match github::repository_identity(&format!("{owner}/{repo}")).await {
            Ok(found) => Some(ForgeRepository {
                owner_id: found
                    .owner_id
                    .filter(|_| under_owner(owner, &found.full_name)),
                project: format!("{host}/{}{subpath}", found.full_name),
                id: found.id,
            }),
            Err(err) => {
                debug!("packslip:{project}: could not look up its repository ID: {err:#}");
                None
            }
        };
    }
    let path = project.strip_prefix("gitlab.com/")?;
    let namespace = path.rsplit_once('/').map_or("", |(namespace, _)| namespace);
    match gitlab::project_identity(path).await {
        Ok(found) => Some(ForgeRepository {
            owner_id: found
                .namespace_id
                .filter(|_| under_owner(namespace, &found.path_with_namespace)),
            project: format!("gitlab.com/{}", found.path_with_namespace),
            id: found.id,
        }),
        Err(err) => {
            debug!("packslip:{project}: could not look up its project ID: {err:#}");
            None
        }
    }
}

/// The project a bundle's statement claims, before anything is verified.
/// Only fit to decide whether a forge lookup is worth making.
fn claimed_project(bundle: &str) -> Option<String> {
    packslip::peek_unverified(bundle)
        .ok()
        .map(|claimed| claimed.project)
}

/// The forge identity a lock entry committed to, if it recorded one.
pub(crate) fn lock_pin(project: &str, info: &PlatformInfo) -> Option<ForgePin> {
    info.signer.as_ref()?;
    let id = info.repository_id.clone()?;
    Some(
        ForgePin::new(project, id, info.repository_owner_id.clone())
            .with_accepted_owner_ids(info.repository_accepted_owner_ids.clone()),
    )
}

/// Record who signed an accepted release in its lock entry: the signer
/// (`scheme:signer`), and the forge identity it was accepted with. Without
/// one, because explicit signer options skip the forge check or the
/// certificate records no IDs, an entry that already named this signer keeps
/// the IDs it recorded, so a commitment is never dropped silently; an entry
/// for another signer loses them with the signer they came with.
pub(crate) fn lock_record(info: &mut PlatformInfo, signer: String, check: Option<&Check>) {
    let same_signer = info.signer.as_deref() == Some(signer.as_str());
    info.signer = Some(signer);
    match check.and_then(|check| check.pin.as_ref()) {
        Some(pin) => {
            info.repository_id = Some(pin.repository_id.clone());
            info.repository_owner_id = pin.owner_id.clone();
            info.repository_accepted_owner_ids = pin.accepted_owner_ids.clone();
        }
        None if same_signer => {}
        None => {
            info.repository_id = None;
            info.repository_owner_id = None;
            info.repository_accepted_owner_ids = Vec::new();
        }
    }
}

/// A signer as a lock entry records it, `scheme:identity`, split in two.
fn split_signer(signer: &str) -> (&str, &str) {
    signer.split_once(':').unwrap_or(("", signer))
}

/// Whether a signer a lock entry recorded (`scheme:signer`) is the one that
/// signed this release: the same string, or the same workflow of the same
/// repository under another name when the forge check passed.
pub(crate) fn lock_signer_continues(locked: &str, signer: &str, check: Option<&Check>) -> bool {
    if locked == signer {
        return true;
    }
    let ((locked_scheme, locked_identity), (scheme, _)) =
        (split_signer(locked), split_signer(signer));
    locked_scheme == scheme && check.is_some_and(|check| check.continues_signer(locked_identity))
}

/// Whether a newly resolved lock entry for `project` is signed by the signer
/// the old one committed to: the same scheme, and the same signer given the
/// forge identity each entry recorded. A rename keeps the signer; a
/// repository ID that changed, or an owner neither entry accepted, does not.
pub(crate) fn lock_entry_continues(project: &str, old: &PlatformInfo, new: &PlatformInfo) -> bool {
    let (Some(previous), Some(current)) = (&old.signer, &new.signer) else {
        return old.signer.is_none();
    };
    let ((previous_scheme, previous), (scheme, current)) =
        (split_signer(previous), split_signer(current));
    previous_scheme == scheme
        && forge::same_workflow(
            previous,
            lock_pin(project, old).as_ref(),
            current,
            lock_pin(project, new).as_ref(),
        )
}

impl ForgeExpect {
    /// The expectation for `project`'s bundle or release list, from this
    /// machine's pin and the lock entries given. With neither, the forge is
    /// asked what the name resolves to, but only when the not yet verified
    /// `bundle` claims another name: under the requested name there is
    /// nothing a first lookup could add, since a new repository that took the
    /// name resolves to itself, and an API request per install would spend a
    /// rate limit that many users share.
    pub(crate) async fn new<'a>(
        project: &str,
        lock: impl IntoIterator<Item = &'a PlatformInfo>,
        bundle: &str,
    ) -> eyre::Result<Self> {
        let mut pins = Vec::new();
        if let Some(pin) = packslip_pins::forge_pin(project)? {
            pins.push((PinSource::Local, pin));
        }
        for pin in lock.into_iter().filter_map(|info| lock_pin(project, info)) {
            let pin = (PinSource::Lockfile, pin);
            if !pins.contains(&pin) {
                pins.push(pin);
            }
        }
        let found = if pins.is_empty() && claimed_project(bundle).as_deref() != Some(project) {
            lookup(project).await
        } else {
            None
        };
        let (resolved, resolved_owner) = match found {
            Some(found) => (Some(found.id), found.owner_id),
            None => (None, None),
        };
        Ok(Self {
            project: project.to_string(),
            pins,
            resolved,
            resolved_owner,
        })
    }

    fn expected(&self) -> Expected<'_> {
        Expected::new(&self.project)
            .pinned_by(&self.pins)
            .resolved(self.resolved.as_deref())
            .resolved_owner(self.resolved_owner.as_deref())
    }

    /// Verify a bundle under the forge's policy and check who signed it.
    pub(crate) fn verify(
        &self,
        bundle: &str,
        options: Options<'_>,
        artifacts: &[&Path],
    ) -> eyre::Result<ForgeVerified<Verified>> {
        packslip::verify_forge(bundle, &self.expected(), options, artifacts)
            .map_err(|err| self.error(err, bundle))
    }

    /// Verify a release list under the forge's policy and check who signed it.
    pub(crate) fn verify_list(
        &self,
        bundle: &str,
        options: Options<'_>,
    ) -> eyre::Result<ForgeVerified<VerifiedList>> {
        packslip::verify_forge_release_list(bundle, &self.expected(), options)
            .map_err(|err| self.error(err, bundle))
    }

    fn error(&self, err: ForgeError, bundle: &str) -> Report {
        match err {
            // The signature verified, or the check would not have run, so the
            // certificate's repository is the release's: it is read again only
            // to tell which pins a recovery has to clear.
            ForgeError::Identity(err) => {
                let source = packslip::sigstore::source_repository(bundle).ok().flatten();
                self.identity_error(err, source.as_ref())
            }
            err => eyre!("{err}"),
        }
    }

    /// Which of the project's pins a release signed as `signed`, whose
    /// certificate records `source`, disagrees with: this machine's, and the
    /// lockfile's. The check stops at the first pin that fails, but a
    /// recovery has to clear every one, or the next install is refused by
    /// the next. Without the certificate's IDs, every pin counts.
    fn disagreeing(
        &self,
        signed: &str,
        source: Option<&SourceRepository>,
        cited: Option<PinSource>,
    ) -> Disagreeing {
        let release = source.and_then(|source| {
            Some(ForgePin::new(
                signed,
                source.id.clone()?,
                source.owner_id.clone(),
            ))
        });
        let disagrees = |pin: &ForgePin| {
            release
                .as_ref()
                .is_none_or(|release| !release.continues(pin))
        };
        let from = |want: PinSource| {
            cited == Some(want)
                || self
                    .pins
                    .iter()
                    .any(|(source, pin)| *source == want && disagrees(pin))
        };
        Disagreeing {
            local: from(PinSource::Local),
            lockfile: from(PinSource::Lockfile),
        }
    }

    fn identity_error(&self, err: IdentityError, source: Option<&SourceRepository>) -> Report {
        let requested = &self.project;
        match err {
            IdentityError::DifferentRepository {
                project,
                expected,
                actual,
                evidence,
            } => {
                let kind = id_kind(requested);
                let refused = "The name now belongs to a different repository, as it would if the original was deleted and someone else created one under its name, so mise refuses it.";
                let Some(cited) = evidence.pin_source() else {
                    return eyre!(
                        "packslip:{requested}: this release was signed by {project} as {kind} {actual}, but {requested} is {kind} {expected} now. \
                         The release comes from a different repository than the one the name belongs to, so mise refuses it."
                    );
                };
                let pinned = match cited {
                    PinSource::Lockfile => "mise.lock pins",
                    _ => "mise pinned",
                };
                let steps = self
                    .disagreeing(&project, source, Some(cited))
                    .steps(requested);
                eyre!(
                    "packslip:{requested}: this release was signed by {project} as {kind} {actual}, but {pinned} {kind} {expected} for it. {refused}\n\n\
                     If the vendor re-created the repository itself, {steps}."
                )
            }
            IdentityError::OwnerChanged(transfer) => {
                let cited = transfer.evidence.and_then(|evidence| evidence.pin_source());
                let disagreeing = self.disagreeing(&transfer.signed, source, cited);
                transfer_error(requested, &transfer, disagreeing)
            }
            err => eyre!("{err}"),
        }
    }
}

/// The pins a refused release disagrees with, by where they came from.
#[derive(Debug, Clone, Copy)]
struct Disagreeing {
    local: bool,
    lockfile: bool,
}

impl Disagreeing {
    /// Every step that clears them, for the project as `requested` names it.
    fn steps(self, requested: &str) -> String {
        let forget = format!("run `mise packslip forget {requested}`");
        let unlock = "remove the tool's entries from mise.lock";
        match (self.local, self.lockfile) {
            (true, true) => format!("{forget}, {unlock}, and install again"),
            (true, false) => format!("{forget} and install again"),
            (false, _) => format!("{unlock} and install again"),
        }
    }
}

/// What `id` is called on the project's forge.
fn id_kind(project: &str) -> &'static str {
    if project.starts_with("gitlab.com/") {
        "GitLab project ID"
    } else {
        "GitHub repository ID"
    }
}

fn transfer_error(requested: &str, transfer: &Transfer, disagreeing: Disagreeing) -> Report {
    let owner = |name: &str, id: Option<&str>| match id {
        Some(id) => format!("{name} (ID {id})"),
        None => name.to_string(),
    };
    let signed = &transfer.signed;
    let now = owner(&transfer.owner, transfer.owner_id.as_deref());
    let before = owner(
        &transfer.previous_owner,
        transfer.previous_owner_id.as_deref(),
    );
    let expected = match transfer.evidence.and_then(|evidence| evidence.pin_source()) {
        Some(PinSource::Lockfile) => format!("mise.lock pins owner {before}"),
        Some(_) => format!("mise pinned owner {before}"),
        None => format!("{requested} has owner {before}"),
    };
    let accept = if signed == requested {
        disagreeing.steps(requested)
    } else if disagreeing.local {
        // This machine's pin is found by the repository's ID under the new
        // name too; the lockfile's entries are the old name's.
        format!("change the tool to packslip:{signed}, and run `mise packslip forget {requested}`")
    } else {
        format!("change the tool to packslip:{signed}")
    };
    eyre!(
        "packslip:{requested}: this release was signed by {signed}, the same repository under another owner: owner {now} signed it, but {expected}. \
         mise follows a repository that was renamed, but not one that changed hands, since trusting the old owner says nothing about the new one.\n\n\
         If {signed} is where the repository lives now and you trust its owner, {accept}."
    )
}

/// Say, once, that a project was installed under a name it no longer has.
/// A release older than a rename is signed under the old name while the
/// config already names the new one, so the forge is asked which is current
/// before anyone is told to change their config.
pub(crate) async fn warn_if_renamed(check: &Check) {
    let Continuity::Renamed { requested, signed } = &check.continuity else {
        return;
    };
    match lookup(requested).await {
        Some(current) if current.project.eq_ignore_ascii_case(signed) => {
            warn_once!(
                "packslip:{requested} was renamed to {signed}; mise followed it by its repository ID. Change the tool to packslip:{signed} in your config"
            );
        }
        _ => debug!(
            "packslip:{requested}: this release was signed under {signed}, the same repository by its ID"
        ),
    }
}

#[cfg(test)]
mod tests {
    use packslip::sigstore::GITHUB_ISSUER;

    use super::*;

    /// jdx/hk's v2.3.0 packslip as its release workflow published it. Its
    /// certificate records repository ID 922514152 and owner ID 216188.
    const HK: &str = include_str!("../test/fixtures/packslip-forge/hk-v2.3.0.sigstore.json");
    const HK_SIGNER: &str = "sigstore-oidc:https://github.com/jdx/hk/.github/workflows/release.yml";
    const HK_ID: &str = "922514152";
    const JDX_ID: &str = "216188";

    /// Verify the hk bundle in full, certificate and all.
    fn verify(expect: &ForgeExpect) -> eyre::Result<ForgeVerified<Verified>> {
        let root = packslip::sigstore::trusted_root(None).unwrap();
        let options = Options {
            require_log: true,
            trusted_root: &root,
        };
        expect.verify(HK, options, &[])
    }

    /// What a certificate for `owner/repo`, of repository `id` and owner
    /// `owner_id`, records.
    fn source(repo: &str, id: &str, owner_id: &str) -> SourceRepository {
        let (owner, _) = repo.split_once('/').unwrap();
        SourceRepository::new(format!("https://github.com/{repo}"))
            .with_id(id)
            .with_owner(format!("https://github.com/{owner}"), owner_id)
    }

    fn hk() -> SourceRepository {
        source("jdx/hk", HK_ID, JDX_ID)
    }

    /// Check a release that `source`'s release workflow signed, as
    /// [`ForgeExpect::verify`] does once the bundle itself verified.
    fn check(expect: &ForgeExpect, source: &SourceRepository) -> eyre::Result<Check> {
        let signed = source.uri.strip_prefix("https://").unwrap();
        let identity = format!("{}/.github/workflows/release.yml@refs/tags/v1", source.uri);
        forge::check(
            &expect.expected(),
            signed,
            &identity,
            Some(GITHUB_ISSUER),
            Some(source),
        )
        .map_err(|err| expect.identity_error(err, Some(source)))
    }

    fn expect(
        project: &str,
        pins: Vec<(PinSource, ForgePin)>,
        resolved: Option<&str>,
    ) -> ForgeExpect {
        ForgeExpect {
            project: project.into(),
            pins,
            resolved: resolved.map(str::to_string),
            resolved_owner: None,
        }
    }

    fn hk_pin(project: &str) -> ForgePin {
        ForgePin::new(project, HK_ID, Some(JDX_ID.into()))
    }

    fn local(pin: ForgePin) -> (PinSource, ForgePin) {
        (PinSource::Local, pin)
    }

    fn locked(pin: ForgePin) -> (PinSource, ForgePin) {
        (PinSource::Lockfile, pin)
    }

    #[test]
    fn the_same_repository_under_its_own_name_is_accepted() {
        for expect in [
            expect("github.com/jdx/hk", vec![], None),
            expect(
                "github.com/jdx/hk",
                vec![local(hk_pin("github.com/jdx/hk"))],
                None,
            ),
            expect(
                "github.com/jdx/hk",
                vec![locked(hk_pin("github.com/jdx/hk"))],
                None,
            ),
        ] {
            let ok = verify(&expect).unwrap();
            assert_eq!(ok.check.continuity, Continuity::Same);
            assert_eq!(ok.check.pin, Some(hk_pin("github.com/jdx/hk")));
            let mut info = PlatformInfo::default();
            lock_record(&mut info, HK_SIGNER.into(), Some(&ok.check));
            assert_eq!(info.signer.as_deref(), Some(HK_SIGNER));
            assert_eq!(info.repository_id.as_deref(), Some(HK_ID));
            assert_eq!(info.repository_owner_id.as_deref(), Some(JDX_ID));
            assert!(info.repository_accepted_owner_ids.is_empty());
            assert_eq!(
                lock_pin("github.com/jdx/hk", &info),
                Some(hk_pin("github.com/jdx/hk"))
            );
        }
    }

    #[test]
    fn a_renamed_project_keeps_installing_by_repository_id() {
        // Were jdx/hk renamed to jdx/hook, a config that says the new name,
        // with the pin or the forge's answer for it, still takes this
        // release signed under the old one.
        for expect in [
            expect(
                "github.com/jdx/hook",
                vec![local(hk_pin("github.com/jdx/hook"))],
                None,
            ),
            expect("github.com/jdx/hook", vec![], Some(HK_ID)),
        ] {
            let ok = verify(&expect).unwrap();
            assert_eq!(
                ok.check.continuity,
                Continuity::Renamed {
                    requested: "github.com/jdx/hook".into(),
                    signed: "github.com/jdx/hk".into(),
                }
            );
            // The signer mise pinned under the new name continues.
            let pinned = "sigstore-oidc:https://github.com/jdx/hook/.github/workflows/release.yml";
            assert!(lock_signer_continues(pinned, HK_SIGNER, Some(&ok.check)));
            assert!(!lock_signer_continues(pinned, HK_SIGNER, None));
            assert!(!lock_signer_continues(
                "sigstore-oidc:https://github.com/jdx/hook/.github/workflows/other.yml",
                HK_SIGNER,
                Some(&ok.check)
            ));
            assert!(!lock_signer_continues(
                "sigstore-key:https://github.com/jdx/hook/.github/workflows/release.yml",
                HK_SIGNER,
                Some(&ok.check)
            ));
        }
        // With nothing to show the names are one repository, another name is
        // refused, as it was before mise knew the IDs.
        let err = verify(&expect("github.com/jdx/hook", vec![], None)).unwrap_err();
        assert!(err.to_string().contains("nothing shows"), "{err}");
    }

    #[test]
    fn a_recreated_name_is_refused() {
        let other = ForgePin::new("github.com/jdx/hk", "1", Some(JDX_ID.into()));
        let err = check(
            &expect("github.com/jdx/hk", vec![local(other.clone())], None),
            &hk(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("belongs to a different repository"), "{msg}");
        assert!(msg.contains("GitHub repository ID 922514152"), "{msg}");
        assert!(
            msg.contains("mise pinned GitHub repository ID 1 for it"),
            "{msg}"
        );
        assert!(
            msg.contains("run `mise packslip forget github.com/jdx/hk` and install again"),
            "{msg}"
        );

        // Every pin must hold, and the refusal says which one did not.
        let err = check(
            &expect(
                "github.com/jdx/hk",
                vec![local(hk_pin("github.com/jdx/hk")), locked(other.clone())],
                None,
            ),
            &hk(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("belongs to a different repository"), "{msg}");
        assert!(
            msg.contains("mise.lock pins GitHub repository ID 1 for it"),
            "{msg}"
        );
        assert!(!msg.contains("mise packslip forget"), "{msg}");

        // This machine's pin fails first, but the lockfile's pins yet another
        // repository: the advice clears both, not only the one cited.
        let err = check(
            &expect(
                "github.com/jdx/hk",
                vec![
                    local(other.clone()),
                    locked(ForgePin::new("github.com/jdx/hk", "2", Some(JDX_ID.into()))),
                ],
                None,
            ),
            &hk(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mise pinned GitHub repository ID 1 for it"),
            "{msg}"
        );
        assert!(
            msg.contains(
                "run `mise packslip forget github.com/jdx/hk`, remove the tool's entries from mise.lock, and install again"
            ),
            "{msg}"
        );
        // And the other way round.
        let err = check(
            &expect(
                "github.com/jdx/hk",
                vec![
                    local(ForgePin::new("github.com/jdx/hk", "2", Some(JDX_ID.into()))),
                    locked(other.clone()),
                ],
                None,
            ),
            &hk(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(
                "run `mise packslip forget github.com/jdx/hk`, remove the tool's entries from mise.lock, and install again"
            ),
            "{err}"
        );
        // Both commit to it: forgetting the pin alone would not do.
        let err = check(
            &expect(
                "github.com/jdx/hk",
                vec![local(other.clone()), locked(other)],
                None,
            ),
            &hk(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(
                "run `mise packslip forget github.com/jdx/hk`, remove the tool's entries from mise.lock, and install again"
            ),
            "{err}"
        );

        let err = check(&expect("github.com/jdx/hook", vec![], Some("555")), &hk()).unwrap_err();
        assert!(
            err.to_string()
                .contains("comes from a different repository than the one the name belongs to"),
            "{err}"
        );
    }

    #[test]
    fn a_transfer_to_another_owner_is_refused() {
        // Were jdx/hk transferred to acme/hk, a config still naming acme's
        // repository by its new name would see a release from before the
        // transfer as signed by jdx.
        let err = check(&expect("github.com/acme/hk", vec![], Some(HK_ID)), &hk()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("the same repository under another owner"),
            "{msg}"
        );
        assert!(
            msg.contains("owner jdx (ID 216188) signed it, but github.com/acme/hk has owner acme"),
            "{msg}"
        );
        assert!(
            msg.contains("change the tool to packslip:github.com/jdx/hk."),
            "{msg}"
        );
        let moved = ForgePin::new("github.com/acme/hk", HK_ID, Some("999".into()));
        let err = check(
            &expect("github.com/acme/hk", vec![locked(moved.clone())], None),
            &hk(),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("but mise.lock pins owner acme (ID 999)"),
            "{err}"
        );
        let err = check(
            &expect("github.com/acme/hk", vec![local(moved)], None),
            &hk(),
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("but mise pinned owner acme (ID 999)"),
            "{err}"
        );
        // This machine's pin would hold the new name to the old owner too.
        assert!(
            err.to_string().contains(
                "change the tool to packslip:github.com/jdx/hk, and run `mise packslip forget github.com/acme/hk`"
            ),
            "{err}"
        );
    }

    #[test]
    fn an_owner_the_pin_accepted_is_not_a_transfer() {
        // A lock entry that accepted acme as well, as a pin does after an
        // accepted transfer, takes a release acme signed and keeps it.
        let pin = hk_pin("github.com/jdx/hk").with_accepted_owner_ids(["999"]);
        let acme = source("acme/hk", HK_ID, "999");
        let ok = check(&expect("github.com/jdx/hk", vec![locked(pin)], None), &acme).unwrap();
        assert!(matches!(ok.continuity, Continuity::Renamed { .. }));
        let mut info = PlatformInfo::default();
        lock_record(&mut info, HK_SIGNER.into(), Some(&ok));
        assert_eq!(info.repository_owner_id.as_deref(), Some("999"));
        assert_eq!(info.repository_accepted_owner_ids, vec![JDX_ID.to_string()]);
        let pin = lock_pin("github.com/jdx/hk", &info).unwrap();
        assert!(pin.accepts_owner(JDX_ID) && pin.accepts_owner("999"));
    }

    #[test]
    fn an_owner_rename_is_told_apart_from_a_transfer() {
        // jdx was called jdx2 when this release was signed. The forge says
        // github.com/jdx/hk is repository 922514152 under owner 216188, the
        // owner that signed, so this is the same owner under a new name.
        let before_rename = source("jdx2/hk", HK_ID, JDX_ID);
        let mut owner_known = expect("github.com/jdx/hk", vec![], Some(HK_ID));
        owner_known.resolved_owner = Some(JDX_ID.into());
        let ok = check(&owner_known, &before_rename).unwrap();
        assert!(matches!(ok.continuity, Continuity::Renamed { .. }));
        // Without the owner's ID, another owner name is a transfer.
        let err = check(
            &expect("github.com/jdx/hk", vec![], Some(HK_ID)),
            &before_rename,
        )
        .unwrap_err();
        assert!(err.to_string().contains("under another owner"), "{err}");
        // And another owner ID is one even under the requested owner's name.
        let retaken = source("jdx/hk", HK_ID, "31337");
        let err = check(&owner_known, &retaken).unwrap_err();
        assert!(
            err.to_string().contains(
                "owner jdx (ID 31337) signed it, but github.com/jdx/hk has owner jdx (ID 216188)"
            ),
            "{err}"
        );
    }

    #[test]
    fn only_an_answer_under_the_requested_owner_gives_its_id() {
        assert!(under_owner("jdx", "jdx/hk"));
        assert!(under_owner("JDX", "jdx/hook"));
        assert!(!under_owner("jdx", "acme/hk"));
        assert!(under_owner("group/sub", "group/sub/tool"));
        assert!(!under_owner("group", "group/sub/tool"));
        assert!(!under_owner("jdx", "hk"));
    }

    #[test]
    fn lock_entries_continue_by_their_forge_ids() {
        let entry = |repo: &str, id: Option<&str>| PlatformInfo {
            signer: Some(format!(
                "sigstore-oidc:https://gitlab.com/{repo}//.gitlab-ci.yml"
            )),
            repository_id: id.map(str::to_string),
            repository_owner_id: id.map(|_| "7".to_string()),
            ..Default::default()
        };
        let project = "gitlab.com/g/tool";
        let old = entry("g/tool", Some("42"));
        assert!(lock_entry_continues(project, &old, &old));
        assert!(lock_entry_continues(
            project,
            &old,
            &entry("g/tool2", Some("42"))
        ));
        assert!(!lock_entry_continues(
            project,
            &old,
            &entry("g/tool", Some("43"))
        ));
        // Without IDs on both sides, the signer itself must be the same.
        let legacy = entry("g/tool", None);
        assert!(lock_entry_continues(project, &legacy, &old));
        assert!(!lock_entry_continues(
            project,
            &legacy,
            &entry("g/tool2", Some("42"))
        ));
        // Another scheme is another signer, whatever the identity.
        let key = PlatformInfo {
            signer: Some("sigstore-key:https://gitlab.com/g/tool//.gitlab-ci.yml".into()),
            ..old.clone()
        };
        assert!(!lock_entry_continues(project, &old, &key));
        // An entry that committed to no signer takes any.
        assert!(lock_entry_continues(
            project,
            &PlatformInfo::default(),
            &old
        ));
        assert!(!lock_entry_continues(
            project,
            &old,
            &PlatformInfo::default()
        ));
    }

    #[test]
    fn a_lock_entry_without_forge_ids_pins_nothing() {
        let info = PlatformInfo {
            signer: Some(HK_SIGNER.into()),
            ..Default::default()
        };
        assert_eq!(lock_pin("github.com/jdx/hk", &info), None);
        let unsigned = PlatformInfo {
            repository_id: Some(HK_ID.into()),
            ..Default::default()
        };
        assert_eq!(lock_pin("github.com/jdx/hk", &unsigned), None);
        let mut cleared = PlatformInfo {
            signer: Some(HK_SIGNER.into()),
            repository_id: Some("1".into()),
            repository_owner_id: Some("2".into()),
            repository_accepted_owner_ids: vec!["3".into()],
            ..Default::default()
        };
        // Explicit signer options check no forge identity: the same signer
        // keeps what its entry recorded...
        lock_record(&mut cleared, HK_SIGNER.into(), None);
        assert_eq!(cleared.repository_id.as_deref(), Some("1"));
        assert_eq!(cleared.repository_owner_id.as_deref(), Some("2"));
        assert_eq!(cleared.repository_accepted_owner_ids, vec!["3".to_string()]);
        // ...and another signer does not inherit it.
        let other = "sigstore-key:5A0A".to_string();
        lock_record(&mut cleared, other.clone(), None);
        assert_eq!(cleared.signer, Some(other));
        assert_eq!(cleared.repository_id, None);
        assert_eq!(cleared.repository_owner_id, None);
        assert!(cleared.repository_accepted_owner_ids.is_empty());
    }

    #[test]
    fn a_machine_pin_follows_the_rename_and_records_the_forge_ids() {
        fn observed(check: Option<&Check>) -> packslip_pins::Observed<'_> {
            packslip_pins::Observed {
                scheme: "sigstore-oidc",
                key_id: "https://github.com/jdx/hk/.github/workflows/release.yml@refs/tags/v2.3.0",
                issuer: Some(GITHUB_ISSUER),
                attested_by: "vendor",
                provenance: false,
                logged: true,
                forge: check,
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.toml");
        // A pin set under the new name, before mise recorded forge IDs.
        let hook = "https://github.com/jdx/hook/.github/workflows/release.yml@refs/tags/v3.0.0";
        packslip_pins::record_at(
            &path,
            "github.com/jdx/hook",
            packslip_pins::Observed {
                key_id: hook,
                ..observed(None)
            },
        )
        .unwrap();
        // A release signed under the old name is another signer by name...
        let err =
            packslip_pins::check_at(&path, "github.com/jdx/hook", observed(None)).unwrap_err();
        assert!(err.to_string().contains("mise packslip forget"), "{err}");
        // ...and the same workflow of the same repository by its ID.
        let check = check(&expect("github.com/jdx/hook", vec![], Some(HK_ID)), &hk()).unwrap();
        packslip_pins::check_at(&path, "github.com/jdx/hook", observed(Some(&check))).unwrap();
        let pin =
            packslip_pins::record_at(&path, "github.com/jdx/hook", observed(Some(&check))).unwrap();
        assert_eq!(pin.forge, Some(hk_pin("github.com/jdx/hk")));
        assert_eq!(
            pin.signer,
            "https://github.com/jdx/hk/.github/workflows/release.yml"
        );
        assert_eq!(
            packslip_pins::forge_pin_at(&path, "github.com/jdx/hook").unwrap(),
            Some(hk_pin("github.com/jdx/hk"))
        );
    }

    #[test]
    fn the_claimed_project_is_read_before_verification() {
        assert_eq!(claimed_project(HK).as_deref(), Some("github.com/jdx/hk"));
        assert_eq!(claimed_project("not a bundle"), None);
    }

    /// What the hk release showed, with `check` the forge check it passed.
    fn hk_observed(check: Option<&Check>, provenance: bool) -> packslip_pins::Observed<'_> {
        packslip_pins::Observed {
            scheme: "sigstore-oidc",
            key_id: "https://github.com/jdx/hk/.github/workflows/release.yml@refs/tags/v2.3.0",
            issuer: Some("https://token.actions.githubusercontent.com"),
            attested_by: "vendor",
            provenance,
            logged: true,
            forge: check,
        }
    }

    /// A pins file with one pin for jdx/hk's repository under `key`, as a
    /// machine that installed it before a rename to jdx/hk wrote it, and a
    /// release-list sequence under the same name.
    fn pins_under(
        key: &str,
        workflow: &str,
        owner_id: &str,
    ) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.toml");
        crate::file::write(
            &path,
            format!(
                r#"[pins."{key}"]
scheme = "sigstore-oidc"
signer = "https://{key}/.github/workflows/{workflow}"
issuer = "https://token.actions.githubusercontent.com"
attested_by = "vendor"
provenance = true
unlogged = false
pinned_at = "2026-09-01T00:00:00Z"

[pins."{key}".forge]
project = "{key}"
repository_id = "922514152"
owner_id = "{owner_id}"

[sequences]
"{key}" = 7
"#
            ),
        )
        .unwrap();
        (dir, path)
    }

    #[test]
    fn a_config_that_follows_a_rename_first_keeps_the_pin() {
        // The config (or another machine's) says jdx/hk while this machine
        // pinned the repository as jdx/old-hk, before any release signed
        // under the new name was accepted. The release's repository ID finds
        // the pin: it is not a first install.
        let (_dir, path) = pins_under("github.com/jdx/old-hk", "release.yml", JDX_ID);
        let check = verify(&expect("github.com/jdx/hk", vec![], None))
            .unwrap()
            .check;
        assert_eq!(check.continuity, Continuity::Same);
        let err =
            packslip_pins::check_at(&path, "github.com/jdx/hk", hk_observed(Some(&check), false))
                .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("drops the build provenance"), "{msg}");
        assert!(
            msg.contains("mise pinned the repository as packslip:github.com/jdx/old-hk"),
            "{msg}"
        );
        assert!(
            msg.contains("mise packslip forget github.com/jdx/old-hk"),
            "{msg}"
        );
        assert!(
            packslip_pins::record_at(&path, "github.com/jdx/hk", hk_observed(Some(&check), false))
                .is_err()
        );

        // What the pin requires, it accepts, and the pin moves to the new
        // name with everything it had: one pin for the repository.
        let pin =
            packslip_pins::record_at(&path, "github.com/jdx/hk", hk_observed(Some(&check), true))
                .unwrap();
        let pins = packslip_pins::list_at(&path).unwrap();
        assert_eq!(
            pins.keys().collect::<Vec<_>>(),
            ["github.com/jdx/hk"],
            "no duplicate pin"
        );
        assert_eq!(pins["github.com/jdx/hk"], pin);
        assert_eq!(pin.pinned_at, "2026-09-01T00:00:00Z");
        assert!(pin.provenance);
        assert_eq!(pin.forge, Some(hk_pin("github.com/jdx/hk")));
        // Its release-list sequence came along.
        let err =
            packslip_pins::check_sequence_at(&path, "github.com/jdx/hk", 6, None).unwrap_err();
        assert!(
            err.to_string().contains("sequence 7 was already accepted"),
            "{err}"
        );
        assert!(packslip_pins::check_missing_list_at(&path, "github.com/jdx/hk", None).is_err());
        // And the name the pin had is still held to it.
        assert!(
            packslip_pins::check_at(
                &path,
                "github.com/jdx/old-hk",
                hk_observed(Some(&check), false),
            )
            .is_err()
        );
    }

    #[test]
    fn a_pin_found_by_repository_id_still_refuses_another_signer() {
        let (_dir, path) = pins_under("github.com/jdx/old-hk", "other.yml", JDX_ID);
        let check = verify(&expect("github.com/jdx/hk", vec![], None))
            .unwrap()
            .check;
        let err =
            packslip_pins::record_at(&path, "github.com/jdx/hk", hk_observed(Some(&check), true))
                .unwrap_err();
        assert!(
            err.to_string().contains("signed what mise accepted before"),
            "{err}"
        );
        let pins = packslip_pins::list_at(&path).unwrap();
        assert_eq!(
            pins.keys().collect::<Vec<_>>(),
            ["github.com/jdx/old-hk"],
            "a refusal moves nothing"
        );
    }

    #[test]
    fn a_pin_found_by_repository_id_still_refuses_a_transfer() {
        // The pin recorded the repository under owner 999; the release is
        // signed by it under jdx (216188).
        let (_dir, path) = pins_under("github.com/acme/hk", "release.yml", "999");
        let check = verify(&expect("github.com/jdx/hk", vec![], None))
            .unwrap()
            .check;
        let err =
            packslip_pins::check_at(&path, "github.com/jdx/hk", hk_observed(Some(&check), true))
                .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(
                "the repository mise pinned as packslip:github.com/acme/hk, but under another owner"
            ),
            "{msg}"
        );
        assert!(
            msg.contains("mise packslip forget github.com/acme/hk"),
            "{msg}"
        );
        assert!(
            packslip_pins::record_at(&path, "github.com/jdx/hk", hk_observed(Some(&check), true))
                .is_err()
        );
    }

    #[test]
    fn another_tool_of_the_same_repository_keeps_its_own_pin() {
        let (_dir, path) = pins_under("github.com/jdx/hk/other", "other.yml", JDX_ID);
        let check = verify(&expect("github.com/jdx/hk", vec![], None))
            .unwrap()
            .check;
        packslip_pins::record_at(&path, "github.com/jdx/hk", hk_observed(Some(&check), false))
            .unwrap();
        let pins = packslip_pins::list_at(&path).unwrap();
        assert_eq!(
            pins.keys().collect::<Vec<_>>(),
            ["github.com/jdx/hk", "github.com/jdx/hk/other"]
        );
    }
}
