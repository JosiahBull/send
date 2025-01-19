//! Build information collected at compile time about the build server.

/// Build information collected at compile time about the build server.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[allow(
    clippy::missing_docs_in_private_items,
    reason = "Self explanatory attribute names"
)]
pub struct BuildInfo {
    pub build_date: String,
    pub build_timestamp: String,
    pub git_branch: String,
    pub git_commit_timestamp: String,
    pub git_describe: String,
    pub git_sha: String,
    // Cargo build info
    pub debug: String,
    pub features: String,
    pub opt_level: String,
    pub target_triple: String,
    pub dependencies: Vec<String>,
    // rustc
    pub rustc_channel: String,
    pub rustc_commit_date: String,
    pub rustc_commit: String,
    pub rustc_version: String,
    pub rustc_host_triple: String,
    pub rustc_semver: String,
    // sys
    pub sysinfo_name: String,
    pub sysinfo_user: String,
    pub sysinfo_os_version: String,
}

impl BuildInfo {
    /// Get the build information from the environment variables set by [`vergen`].
    #[allow(
        clippy::manual_string_new,
        reason = "False positive depending on environment variables"
    )]
    pub fn get_buildinfo() -> Self {
        Self {
            build_date: String::from(env!("VERGEN_BUILD_DATE")),
            build_timestamp: String::from(env!("VERGEN_BUILD_TIMESTAMP")),
            git_branch: String::from(env!("VERGEN_GIT_BRANCH")),
            git_commit_timestamp: String::from(env!("VERGEN_GIT_COMMIT_TIMESTAMP")),
            git_describe: String::from(env!("VERGEN_GIT_DESCRIBE")),
            git_sha: String::from(env!("VERGEN_GIT_SHA")),
            debug: String::from(env!("VERGEN_CARGO_DEBUG")),
            features: String::from(env!("VERGEN_CARGO_FEATURES")),
            opt_level: String::from(env!("VERGEN_CARGO_OPT_LEVEL")),
            target_triple: String::from(env!("VERGEN_CARGO_TARGET_TRIPLE")),
            dependencies: env!("VERGEN_CARGO_DEPENDENCIES")
                .split(',')
                .map(|s| s.to_string())
                .collect(),
            rustc_channel: String::from(env!("VERGEN_RUSTC_CHANNEL")),
            rustc_commit_date: String::from(env!("VERGEN_RUSTC_COMMIT_DATE")),
            rustc_commit: String::from(env!("VERGEN_RUSTC_COMMIT_HASH")),
            rustc_version: String::from(env!("VERGEN_RUSTC_SEMVER")),
            rustc_host_triple: String::from(env!("VERGEN_RUSTC_HOST_TRIPLE")),
            rustc_semver: String::from(env!("VERGEN_RUSTC_SEMVER")),
            sysinfo_name: String::from(env!("VERGEN_SYSINFO_NAME")),
            sysinfo_user: String::from(env!("VERGEN_SYSINFO_USER")),
            sysinfo_os_version: String::from(env!("VERGEN_SYSINFO_OS_VERSION")),
        }
    }
}

#[cfg_attr(test, mutants::skip)]
impl std::fmt::Display for BuildInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            build_date,
            build_timestamp,
            git_branch,
            git_commit_timestamp,
            git_describe,
            git_sha,
            debug,
            features,
            opt_level,
            target_triple,
            dependencies,
            rustc_channel,
            rustc_commit_date,
            rustc_commit,
            rustc_version,
            rustc_host_triple,
            rustc_semver,
            sysinfo_name,
            sysinfo_user,
            sysinfo_os_version,
        } = self;

        writeln!(f, "Commit Info")?;
        writeln!(
            f,
            "============================================================"
        )?;
        writeln!(f, "{:20}{}", "Commit Branch:", git_branch)?;
        writeln!(f, "{:20}{}", "Commit Timestamp:", git_commit_timestamp)?;
        writeln!(f, "{:20}{}", "Commit version:", git_describe)?;
        writeln!(f, "{:20}{}", "Commit SHA:", git_sha)?;
        writeln!(f, "{:20}{}", "Commit Date:", rustc_commit_date)?;
        writeln!(f)?;
        writeln!(f, "Build Info")?;
        writeln!(
            f,
            "============================================================"
        )?;
        writeln!(f, "{:20}{}", "Build Target:", target_triple)?;
        writeln!(f, "{:20}{}", "Build Date:", build_date)?;
        writeln!(f, "{:20}{}", "Build Timestamp:", build_timestamp)?;
        writeln!(
            f,
            "{:20}{}",
            "Build Profile:",
            if debug == "true" { "debug" } else { "release" }
        )?;
        writeln!(f, "{:20}{}", "Features:", features)?;
        writeln!(f, "{:20}{}", "Opt Level:", opt_level)?;
        writeln!(f, "{:20}{}", "rustc Channel", rustc_channel)?;
        writeln!(f, "{:20}{}", "rustc Version:", rustc_commit)?;
        writeln!(f, "{:20}{}", "rustc Commit:", rustc_version)?;
        writeln!(f, "{:20}{}", "rustc Semver:", rustc_semver)?;
        writeln!(f, "{:20}{}", "rustc Host:", rustc_host_triple)?;
        for dep in dependencies {
            writeln!(f, "{:20}{}", "Dependency:", dep)?;
        }
        writeln!(f)?;
        writeln!(f, "Build System Info")?;
        writeln!(
            f,
            "============================================================"
        )?;
        writeln!(f, "{:20}{}", "Build User:", sysinfo_user)?;
        writeln!(f, "{:20}{}", "Build System Name:", sysinfo_name)?;
        writeln!(f, "{:20}{}", "Build OS Version:", sysinfo_os_version)?;

        Ok(())
    }
}
