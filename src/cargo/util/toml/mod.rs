use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str;

use anyhow::{anyhow, bail};
use cargo_platform::Platform;
use log::{debug, trace};
use semver::{self, VersionReq};
use serde::de;
use serde::ser;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::core::dependency::DepKind;
use crate::core::manifest::{ManifestMetadata, TargetSourcePath, Warnings};
use crate::core::nightly_features_allowed;
use crate::core::profiles::Strip;
use crate::core::resolver::ResolveBehavior;
use crate::core::{Dependency, Manifest, PackageId, Summary, Target};
use crate::core::{Edition, EitherManifest, Feature, Features, InheritableFields, VirtualManifest};
use crate::core::{
    GitReference, PackageIdSpec, SourceId, Workspace, WorkspaceConfig, WorkspaceRootConfig,
};
use crate::sources::{CRATES_IO_INDEX, CRATES_IO_REGISTRY};
use crate::util::errors::{CargoResult, CargoResultExt, ManifestError};
use crate::util::interning::InternedString;
use crate::util::{self, paths, validate_package_name, Config, IntoUrl};

mod targets;
use self::targets::targets;

/// Loads a `Cargo.toml` from a file on disk.
///
/// This could result in a real or virtual manifest being returned.
///
/// A list of nested paths is also returned, one for each path dependency
/// within the manfiest. For virtual manifests, these paths can only
/// come from patched or replaced dependencies. These paths are not
/// canonicalized.
pub fn read_manifest(
    path: &Path,
    source_id: SourceId,
    config: &Config,
    inheritable: &InheritableFields,
) -> Result<(EitherManifest, Vec<PathBuf>), ManifestError> {
    trace!(
        "read_manifest; path={}; source-id={}",
        path.display(),
        source_id
    );
    let contents = paths::read(path).map_err(|err| ManifestError::new(err, path.into()))?;

    do_read_manifest(&contents, path, source_id, config, inheritable)
        .chain_err(|| format!("failed to parse manifest at `{}`", path.display()))
        .map_err(|err| ManifestError::new(err, path.into()))
}

fn do_read_manifest(
    contents: &str,
    manifest_file: &Path,
    source_id: SourceId,
    config: &Config,
    inheritable: &InheritableFields,
) -> CargoResult<(EitherManifest, Vec<PathBuf>)> {
    let package_root = manifest_file.parent().unwrap();

    let toml = {
        let pretty_filename = manifest_file
            .strip_prefix(config.cwd())
            .unwrap_or(manifest_file);
        parse(contents, pretty_filename, config)?
    };

    // Provide a helpful error message for a common user error.
    if let Some(package) = toml.get("package").or_else(|| toml.get("project")) {
        if let Some(feats) = package.get("cargo-features") {
            bail!(
                "cargo-features = {} was found in the wrong location, it \
                 should be set at the top of Cargo.toml before any tables",
                toml::to_string(feats).unwrap()
            );
        }
    }

    let mut unused = BTreeSet::new();
    let manifest: TomlManifest = serde_ignored::deserialize(toml, |path| {
        let mut key = String::new();
        stringify(&mut key, &path);
        unused.insert(key);
    })?;
    let add_unused = |warnings: &mut Warnings| {
        for key in unused {
            warnings.add_warning(format!("unused manifest key: {}", key));
            if key == "profiles.debug" {
                warnings.add_warning("use `[profile.dev]` to configure debug builds".to_string());
            }
        }
    };

    let manifest = Rc::new(manifest);
    return if manifest.project.is_some() || manifest.package.is_some() {
        let (mut manifest, paths) = TomlManifest::to_real_manifest(
            &manifest,
            source_id,
            package_root,
            config,
            inheritable,
        )?;
        add_unused(manifest.warnings_mut());
        if manifest.targets().iter().all(|t| t.is_custom_build()) {
            bail!(
                "no targets specified in the manifest\n\
                 either src/lib.rs, src/main.rs, a [lib] section, or \
                 [[bin]] section must be present"
            )
        }
        Ok((EitherManifest::Real(manifest), paths))
    } else {
        let (mut m, paths) =
            TomlManifest::to_virtual_manifest(&manifest, source_id, package_root, config)?;
        add_unused(m.warnings_mut());
        Ok((EitherManifest::Virtual(m), paths))
    };

    fn stringify(dst: &mut String, path: &serde_ignored::Path<'_>) {
        use serde_ignored::Path;

        match *path {
            Path::Root => {}
            Path::Seq { parent, index } => {
                stringify(dst, parent);
                if !dst.is_empty() {
                    dst.push('.');
                }
                dst.push_str(&index.to_string());
            }
            Path::Map { parent, ref key } => {
                stringify(dst, parent);
                if !dst.is_empty() {
                    dst.push('.');
                }
                dst.push_str(key);
            }
            Path::Some { parent }
            | Path::NewtypeVariant { parent }
            | Path::NewtypeStruct { parent } => stringify(dst, parent),
        }
    }
}

/// Attempts to parse a string into a [`toml::Value`]. This is not specific to any
/// particular kind of TOML file.
///
/// The purpose of this wrapper is to detect invalid TOML which was previously
/// accepted and display a warning to the user in that case. The `file` and `config`
/// parameters are only used by this fallback path.
pub fn parse(toml: &str, file: &Path, config: &Config) -> CargoResult<toml::Value> {
    let first_error = match toml.parse() {
        Ok(ret) => return Ok(ret),
        Err(e) => e,
    };

    let mut second_parser = toml::de::Deserializer::new(toml);
    second_parser.set_require_newline_after_table(false);
    if let Ok(ret) = toml::Value::deserialize(&mut second_parser) {
        let msg = format!(
            "\
TOML file found which contains invalid syntax and will soon not parse
at `{}`.

The TOML spec requires newlines after table definitions (e.g., `[a] b = 1` is
invalid), but this file has a table header which does not have a newline after
it. A newline needs to be added and this warning will soon become a hard error
in the future.",
            file.display()
        );
        config.shell().warn(&msg)?;
        return Ok(ret);
    }

    let mut third_parser = toml::de::Deserializer::new(toml);
    third_parser.set_allow_duplicate_after_longer_table(true);
    if let Ok(ret) = toml::Value::deserialize(&mut third_parser) {
        let msg = format!(
            "\
TOML file found which contains invalid syntax and will soon not parse
at `{}`.

The TOML spec requires that each table header is defined at most once, but
historical versions of Cargo have erroneously accepted this file. The table
definitions will need to be merged together with one table header to proceed,
and this will become a hard error in the future.",
            file.display()
        );
        config.shell().warn(&msg)?;
        return Ok(ret);
    }

    let first_error = anyhow::Error::from(first_error);
    Err(first_error.context("could not parse input as TOML"))
}

type TomlLibTarget = TomlTarget;
type TomlBinTarget = TomlTarget;
type TomlExampleTarget = TomlTarget;
type TomlTestTarget = TomlTarget;
type TomlBenchTarget = TomlTarget;

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum TomlDependency {
    /// In the simple format, only a version is specified, eg.
    /// `package = "<version>"`
    Simple(String),
    /// The simple format is equivalent to a detailed dependency
    /// specifying only a version, eg.
    /// `package = { version = "<version>" }`
    Detailed(DetailedTomlDependency),
}

impl<'de> de::Deserialize<'de> for TomlDependency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct TomlDependencyVisitor;

        impl<'de> de::Visitor<'de> for TomlDependencyVisitor {
            type Value = TomlDependency;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(
                    "a version string like \"0.9.8\" or a \
                     detailed dependency like { version = \"0.9.8\" }",
                )
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(TomlDependency::Simple(s.to_owned()))
            }

            fn visit_map<V>(self, map: V) -> Result<Self::Value, V::Error>
            where
                V: de::MapAccess<'de>,
            {
                let mvd = de::value::MapAccessDeserializer::new(map);
                DetailedTomlDependency::deserialize(mvd).map(TomlDependency::Detailed)
            }
        }

        deserializer.deserialize_any(TomlDependencyVisitor)
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
#[serde(rename_all = "kebab-case")]
pub struct DetailedTomlDependency {
    version: Option<String>,
    registry: Option<String>,
    /// The URL of the `registry` field.
    /// This is an internal implementation detail. When Cargo creates a
    /// package, it replaces `registry` with `registry-index` so that the
    /// manifest contains the correct URL. All users won't have the same
    /// registry names configured, so Cargo can't rely on just the name for
    /// crates published by other users.
    registry_index: Option<String>,
    path: Option<String>,
    git: Option<String>,
    branch: Option<String>,
    tag: Option<String>,
    rev: Option<String>,
    features: Option<Vec<String>>,
    optional: Option<bool>,
    default_features: Option<bool>,
    #[serde(rename = "default_features")]
    default_features2: Option<bool>,
    package: Option<String>,
    public: Option<bool>,
}

/// This type is used to deserialize `Cargo.toml` files.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TomlManifest {
    cargo_features: Option<Vec<String>>,
    package: Option<Box<TomlProject>>,
    project: Option<Box<TomlProject>>,
    profile: Option<TomlProfiles>,
    lib: Option<TomlLibTarget>,
    bin: Option<Vec<TomlBinTarget>>,
    example: Option<Vec<TomlExampleTarget>>,
    test: Option<Vec<TomlTestTarget>>,
    bench: Option<Vec<TomlTestTarget>>,
    dependencies: Option<BTreeMap<String, MaybeWorkspace<TomlDependency>>>,
    dev_dependencies: Option<BTreeMap<String, TomlDependency>>,
    #[serde(rename = "dev_dependencies")]
    dev_dependencies2: Option<BTreeMap<String, TomlDependency>>,
    build_dependencies: Option<BTreeMap<String, TomlDependency>>,
    #[serde(rename = "build_dependencies")]
    build_dependencies2: Option<BTreeMap<String, TomlDependency>>,
    features: Option<BTreeMap<InternedString, Vec<InternedString>>>,
    target: Option<BTreeMap<String, TomlPlatform>>,
    replace: Option<BTreeMap<String, TomlDependency>>,
    patch: Option<BTreeMap<String, BTreeMap<String, TomlDependency>>>,
    workspace: Option<TomlWorkspace>,
    badges: Option<BTreeMap<String, MaybeWorkspace<BTreeMap<String, String>>>>,
}

impl TomlManifest {
    pub fn hydrated_dependencies(
        &self,
        inheritable: &InheritableFields,
    ) -> CargoResult<Option<BTreeMap<String, TomlDependency>>> {
        self.dependencies
            .as_ref()
            .map(|deps| {
                deps.iter()
                    .map(|(name, dep)| match dep {
                        MaybeWorkspace::Defined(d) => Ok((name.clone(), d.clone())),
                        MaybeWorkspace::Workspace => inheritable
                            .dependency(name)
                            .map(|inherited| (name.clone(), inherited))
                            .ok_or(anyhow!("{} not present in parent workspace!", name)),
                    })
                    .collect::<CargoResult<BTreeMap<String, TomlDependency>>>()
            })
            .map_or(Ok(None), |v| v.map(Some))
    }

    pub fn hydrated_badges(
        &self,
        inheritable: &InheritableFields,
    ) -> CargoResult<Option<BTreeMap<String, BTreeMap<String, String>>>> {
        self.badges
            .as_ref()
            .map(|badges| {
                badges
                    .iter()
                    .map(|(name, badge)| match badge {
                        MaybeWorkspace::Defined(b) => Ok((name.clone(), b.clone())),
                        MaybeWorkspace::Workspace => inheritable
                            .badge(name)
                            .map(|inherited| (name.clone(), inherited))
                            .ok_or(anyhow!("{} not present in parent workspace!", name)),
                    })
                    .collect::<CargoResult<BTreeMap<String, BTreeMap<String, String>>>>()
            })
            .map_or(Ok(None), |v| v.map(Some))
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct TomlProfiles(BTreeMap<InternedString, TomlProfile>);

impl TomlProfiles {
    pub fn get_all(&self) -> &BTreeMap<InternedString, TomlProfile> {
        &self.0
    }

    pub fn get(&self, name: &str) -> Option<&TomlProfile> {
        self.0.get(name)
    }

    pub fn validate(&self, features: &Features, warnings: &mut Vec<String>) -> CargoResult<()> {
        for (name, profile) in &self.0 {
            profile.validate(name, features, warnings)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TomlOptLevel(pub String);

impl<'de> de::Deserialize<'de> for TomlOptLevel {
    fn deserialize<D>(d: D) -> Result<TomlOptLevel, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = TomlOptLevel;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an optimization level")
            }

            fn visit_i64<E>(self, value: i64) -> Result<TomlOptLevel, E>
            where
                E: de::Error,
            {
                Ok(TomlOptLevel(value.to_string()))
            }

            fn visit_str<E>(self, value: &str) -> Result<TomlOptLevel, E>
            where
                E: de::Error,
            {
                if value == "s" || value == "z" {
                    Ok(TomlOptLevel(value.to_string()))
                } else {
                    Err(E::custom(format!(
                        "must be an integer, `z`, or `s`, \
                         but found the string: \"{}\"",
                        value
                    )))
                }
            }
        }

        d.deserialize_any(Visitor)
    }
}

impl ser::Serialize for TomlOptLevel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        match self.0.parse::<u32>() {
            Ok(n) => n.serialize(serializer),
            Err(_) => self.0.serialize(serializer),
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum U32OrBool {
    U32(u32),
    Bool(bool),
}

impl<'de> de::Deserialize<'de> for U32OrBool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = U32OrBool;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a boolean or an integer")
            }

            fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(U32OrBool::Bool(b))
            }

            fn visit_i64<E>(self, u: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(U32OrBool::U32(u as u32))
            }

            fn visit_u64<E>(self, u: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(U32OrBool::U32(u as u32))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, Eq, PartialEq)]
#[serde(default, rename_all = "kebab-case")]
pub struct TomlProfile {
    pub opt_level: Option<TomlOptLevel>,
    pub lto: Option<StringOrBool>,
    pub codegen_units: Option<u32>,
    pub debug: Option<U32OrBool>,
    pub debug_assertions: Option<bool>,
    pub rpath: Option<bool>,
    pub panic: Option<String>,
    pub overflow_checks: Option<bool>,
    pub incremental: Option<bool>,
    pub package: Option<BTreeMap<ProfilePackageSpec, TomlProfile>>,
    pub build_override: Option<Box<TomlProfile>>,
    pub dir_name: Option<InternedString>,
    pub inherits: Option<InternedString>,
    pub strip: Option<Strip>,
}

#[derive(Clone, Debug, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum ProfilePackageSpec {
    Spec(PackageIdSpec),
    All,
}

impl ser::Serialize for ProfilePackageSpec {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        match *self {
            ProfilePackageSpec::Spec(ref spec) => spec.serialize(s),
            ProfilePackageSpec::All => "*".serialize(s),
        }
    }
}

impl<'de> de::Deserialize<'de> for ProfilePackageSpec {
    fn deserialize<D>(d: D) -> Result<ProfilePackageSpec, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let string = String::deserialize(d)?;
        if string == "*" {
            Ok(ProfilePackageSpec::All)
        } else {
            PackageIdSpec::parse(&string)
                .map_err(de::Error::custom)
                .map(ProfilePackageSpec::Spec)
        }
    }
}

impl TomlProfile {
    pub fn validate(
        &self,
        name: &str,
        features: &Features,
        warnings: &mut Vec<String>,
    ) -> CargoResult<()> {
        if name == "debug" {
            warnings.push("use `[profile.dev]` to configure debug builds".to_string());
        }

        if let Some(ref profile) = self.build_override {
            features.require(Feature::profile_overrides())?;
            profile.validate_override("build-override")?;
        }
        if let Some(ref packages) = self.package {
            features.require(Feature::profile_overrides())?;
            for profile in packages.values() {
                profile.validate_override("package")?;
            }
        }

        // Feature gate definition of named profiles
        match name {
            "dev" | "release" | "bench" | "test" | "doc" => {}
            _ => {
                features.require(Feature::named_profiles())?;
            }
        }

        // Profile name validation
        Self::validate_name(name, "profile name")?;

        // Feature gate on uses of keys related to named profiles
        if self.inherits.is_some() {
            features.require(Feature::named_profiles())?;
        }

        if self.dir_name.is_some() {
            features.require(Feature::named_profiles())?;
        }

        // `dir-name` validation
        match &self.dir_name {
            None => {}
            Some(dir_name) => {
                Self::validate_name(dir_name, "dir-name")?;
            }
        }

        // `inherits` validation
        match &self.inherits {
            None => {}
            Some(inherits) => {
                Self::validate_name(inherits, "inherits")?;
            }
        }

        match name {
            "doc" => {
                warnings.push("profile `doc` is deprecated and has no effect".to_string());
            }
            "test" | "bench" => {
                if self.panic.is_some() {
                    warnings.push(format!("`panic` setting is ignored for `{}` profile", name))
                }
            }
            _ => {}
        }

        if let Some(panic) = &self.panic {
            if panic != "unwind" && panic != "abort" {
                bail!(
                    "`panic` setting of `{}` is not a valid setting,\
                     must be `unwind` or `abort`",
                    panic
                );
            }
        }

        if self.strip.is_some() {
            features.require(Feature::strip())?;
        }
        Ok(())
    }

    /// Validate dir-names and profile names according to RFC 2678.
    pub fn validate_name(name: &str, what: &str) -> CargoResult<()> {
        if let Some(ch) = name
            .chars()
            .find(|ch| !ch.is_alphanumeric() && *ch != '_' && *ch != '-')
        {
            bail!("Invalid character `{}` in {}: `{}`", ch, what, name);
        }

        match name {
            "package" | "build" => {
                bail!("Invalid {}: `{}`", what, name);
            }
            "debug" if what == "profile" => {
                if what == "profile name" {
                    // Allowed, but will emit warnings
                } else {
                    bail!("Invalid {}: `{}`", what, name);
                }
            }
            "doc" if what == "dir-name" => {
                bail!("Invalid {}: `{}`", what, name);
            }
            _ => {}
        }

        Ok(())
    }

    fn validate_override(&self, which: &str) -> CargoResult<()> {
        if self.package.is_some() {
            bail!("package-specific profiles cannot be nested");
        }
        if self.build_override.is_some() {
            bail!("build-override profiles cannot be nested");
        }
        if self.panic.is_some() {
            bail!("`panic` may not be specified in a `{}` profile", which)
        }
        if self.lto.is_some() {
            bail!("`lto` may not be specified in a `{}` profile", which)
        }
        if self.rpath.is_some() {
            bail!("`rpath` may not be specified in a `{}` profile", which)
        }
        Ok(())
    }

    /// Overwrite self's values with the given profile.
    pub fn merge(&mut self, profile: &TomlProfile) {
        if let Some(v) = &profile.opt_level {
            self.opt_level = Some(v.clone());
        }

        if let Some(v) = &profile.lto {
            self.lto = Some(v.clone());
        }

        if let Some(v) = profile.codegen_units {
            self.codegen_units = Some(v);
        }

        if let Some(v) = &profile.debug {
            self.debug = Some(v.clone());
        }

        if let Some(v) = profile.debug_assertions {
            self.debug_assertions = Some(v);
        }

        if let Some(v) = profile.rpath {
            self.rpath = Some(v);
        }

        if let Some(v) = &profile.panic {
            self.panic = Some(v.clone());
        }

        if let Some(v) = profile.overflow_checks {
            self.overflow_checks = Some(v);
        }

        if let Some(v) = profile.incremental {
            self.incremental = Some(v);
        }

        if let Some(other_package) = &profile.package {
            match &mut self.package {
                Some(self_package) => {
                    for (spec, other_pkg_profile) in other_package {
                        match self_package.get_mut(spec) {
                            Some(p) => p.merge(other_pkg_profile),
                            None => {
                                self_package.insert(spec.clone(), other_pkg_profile.clone());
                            }
                        }
                    }
                }
                None => self.package = Some(other_package.clone()),
            }
        }

        if let Some(other_bo) = &profile.build_override {
            match &mut self.build_override {
                Some(self_bo) => self_bo.merge(other_bo),
                None => self.build_override = Some(other_bo.clone()),
            }
        }

        if let Some(v) = &profile.inherits {
            self.inherits = Some(*v);
        }

        if let Some(v) = &profile.dir_name {
            self.dir_name = Some(*v);
        }

        if let Some(v) = profile.strip {
            self.strip = Some(v);
        }
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub struct StringOrVec(Vec<String>);

impl<'de> de::Deserialize<'de> for StringOrVec {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = StringOrVec;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("string or list of strings")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StringOrVec(vec![s.to_string()]))
            }

            fn visit_seq<V>(self, v: V) -> Result<Self::Value, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let seq = de::value::SeqAccessDeserializer::new(v);
                Vec::deserialize(seq).map(StringOrVec)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum StringOrBool {
    String(String),
    Bool(bool),
}

impl<'de> de::Deserialize<'de> for StringOrBool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = StringOrBool;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a boolean or a string")
            }

            fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StringOrBool::Bool(b))
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StringOrBool::String(s.to_string()))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

#[derive(PartialEq, Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum VecStringOrBool {
    VecString(Vec<String>),
    Bool(bool),
}

impl<'de> de::Deserialize<'de> for VecStringOrBool {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = VecStringOrBool;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a boolean or vector of strings")
            }

            fn visit_seq<V>(self, v: V) -> Result<Self::Value, V::Error>
            where
                V: de::SeqAccess<'de>,
            {
                let seq = de::value::SeqAccessDeserializer::new(v);
                Vec::deserialize(seq).map(VecStringOrBool::VecString)
            }

            fn visit_bool<E>(self, b: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(VecStringOrBool::Bool(b))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

/// Represents the `package`/`project` sections of a `Cargo.toml`.
///
/// Note that the order of the fields matters, since this is the order they
/// are serialized to a TOML file. For example, you cannot have values after
/// the field `metadata`, since it is a table and values cannot appear after
/// tables.
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct TomlProject {
    edition: Option<MaybeWorkspace<String>>,
    rust_version: Option<String>,
    name: InternedString,
    version: MaybeWorkspace<semver::Version>,
    authors: Option<MaybeWorkspace<Vec<String>>>,
    build: Option<StringOrBool>,
    metabuild: Option<StringOrVec>,
    links: Option<String>,
    exclude: Option<Vec<String>>,
    include: Option<Vec<String>>,
    publish: Option<MaybeWorkspace<VecStringOrBool>>,
    workspace: Option<String>,
    im_a_teapot: Option<bool>,
    autobins: Option<bool>,
    autoexamples: Option<bool>,
    autotests: Option<bool>,
    autobenches: Option<bool>,
    default_run: Option<String>,

    // Package metadata.
    description: Option<MaybeWorkspace<String>>,
    homepage: Option<MaybeWorkspace<String>>,
    documentation: Option<MaybeWorkspace<String>>,
    readme: Option<MaybeWorkspace<StringOrBool>>,
    keywords: Option<MaybeWorkspace<Vec<String>>>,
    categories: Option<MaybeWorkspace<Vec<String>>>,
    license: Option<MaybeWorkspace<String>>,
    license_file: Option<MaybeWorkspace<String>>,
    repository: Option<MaybeWorkspace<String>>,
    metadata: Option<toml::Value>,
    resolver: Option<String>,
}

macro_rules! inherit_from_ws {
    ($this: ident, $inheritable: ident, $field: ident) => {
        match $this.$field.as_ref() {
            Some(MaybeWorkspace::Defined(v)) => Some(v),
            Some(MaybeWorkspace::Workspace) => $inheritable.$field.as_ref(),
            None => None,
        }
    };
}

macro_rules! unwrap_from_ws {
    ($this: ident, $inheritable: ident, $field: ident) => {
        match $this.$field {
            MaybeWorkspace::Defined(ref v) => Ok(v),
            MaybeWorkspace::Workspace => $inheritable.$field.as_ref().ok_or(anyhow!(
                "{} not present in parent workspace!",
                stringify!($field)
            )),
        }
    };
}

impl TomlProject {
    pub fn hydrated_edition<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a String> {
        inherit_from_ws!(self, inheritable, edition)
    }

    pub fn hydrated_version<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> CargoResult<&'a semver::Version> {
        unwrap_from_ws!(self, inheritable, version)
    }

    pub fn hydrated_authors<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a Vec<String>> {
        inherit_from_ws!(self, inheritable, authors)
    }

    pub fn hydrated_publish<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a VecStringOrBool> {
        inherit_from_ws!(self, inheritable, publish)
    }

    pub fn hydrated_description<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a String> {
        inherit_from_ws!(self, inheritable, description)
    }

    pub fn hydrated_homepage<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a String> {
        inherit_from_ws!(self, inheritable, homepage)
    }

    pub fn hydrated_documentation<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a String> {
        inherit_from_ws!(self, inheritable, documentation)
    }

    pub fn hydrated_readme<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a StringOrBool> {
        inherit_from_ws!(self, inheritable, readme)
    }

    pub fn hydrated_keywords<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a Vec<String>> {
        inherit_from_ws!(self, inheritable, keywords)
    }

    pub fn hydrated_categories<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a Vec<String>> {
        inherit_from_ws!(self, inheritable, categories)
    }

    pub fn hydrated_license<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a String> {
        inherit_from_ws!(self, inheritable, license)
    }

    pub fn hydrated_license_file<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a String> {
        inherit_from_ws!(self, inheritable, license_file)
    }

    pub fn hydrated_repository<'a>(
        &'a self,
        inheritable: &'a InheritableFields,
    ) -> Option<&'a String> {
        inherit_from_ws!(self, inheritable, repository)
    }

    pub fn to_package_id(
        &self,
        source_id: SourceId,
        inheritable: &InheritableFields,
    ) -> CargoResult<PackageId> {
        let version = self.hydrated_version(inheritable)?;
        PackageId::new(self.name, version, source_id)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TomlWorkspace {
    pub members: Option<Vec<String>>,
    pub default_members: Option<Vec<String>>,
    pub exclude: Option<Vec<String>>,
    pub metadata: Option<toml::Value>,
    pub resolver: Option<String>,

    // Fields that can be inherited by members
    pub dependencies: Option<BTreeMap<String, TomlDependency>>,
    pub version: Option<semver::Version>,
    pub authors: Option<Vec<String>>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub documentation: Option<String>,
    pub readme: Option<StringOrBool>,
    pub keywords: Option<Vec<String>>,
    pub categories: Option<Vec<String>>,
    pub license: Option<String>,
    pub license_file: Option<String>,
    pub repository: Option<String>,
    pub publish: Option<VecStringOrBool>,
    pub edition: Option<String>,
    pub badges: Option<BTreeMap<String, BTreeMap<String, String>>>,
}

struct Context<'a, 'b> {
    pkgid: Option<PackageId>,
    deps: &'a mut Vec<Dependency>,
    source_id: SourceId,
    nested_paths: &'a mut Vec<PathBuf>,
    config: &'b Config,
    warnings: &'a mut Vec<String>,
    platform: Option<Platform>,
    root: &'a Path,
    features: &'a Features,
}

impl TomlManifest {
    /// Prepares the manfiest for publishing.
    /// - Path and git components of dependency specifications are removed.
    /// - License path is updated to point within the package.
    /// - The package's workspace needs to be None
    /// - The package's resolver needs to be set to the workspace's
    /// - Fields inherited from the workspace are hydrated
    pub fn prepare_for_publish(
        &self,
        ws: &Workspace<'_>,
        package_root: &Path,
    ) -> CargoResult<TomlManifest> {
        let config = ws.config();
        let inheritable = ws.inheritable_fields();

        /// Dependencies need to be updated to make sense, when this crate is stand-alone.
        /// Specifically:
        /// 1. Path and Git components of dependency specifications are removed
        fn map_dependencies(
            config: &Config,
            deps: Option<&BTreeMap<String, TomlDependency>>,
            filter: impl Fn(&TomlDependency) -> bool,
        ) -> CargoResult<Option<BTreeMap<String, TomlDependency>>> {
            let deps = match deps {
                Some(deps) => deps,
                None => return Ok(None),
            };

            let map_dependency = |dep: &TomlDependency| -> CargoResult<TomlDependency> {
                match dep {
                    TomlDependency::Detailed(d) => {
                        let mut d = d.clone();
                        // Path dependencies become crates.io deps.
                        d.path.take();
                        // Same with git dependencies.
                        d.git.take();
                        d.branch.take();
                        d.tag.take();
                        d.rev.take();
                        // registry specifications are elaborated to the index URL
                        if let Some(registry) = d.registry.take() {
                            let src = SourceId::alt_registry(config, &registry)?;
                            d.registry_index = Some(src.url().to_string());
                        }
                        Ok(TomlDependency::Detailed(d))
                    }
                    TomlDependency::Simple(s) => {
                        Ok(TomlDependency::Detailed(DetailedTomlDependency {
                            version: Some(s.clone()),
                            ..Default::default()
                        }))
                    }
                }
            };

            let deps = deps
                .iter()
                .filter(|(_k, v)| filter(v))
                .map(|(k, v)| Ok((k.clone(), map_dependency(v)?)))
                .collect::<CargoResult<BTreeMap<_, _>>>()?;
            Ok(Some(deps))
        }

        /// The Package/Project needs to be updated to updated to make sense, when this crate
        /// is stand-alone.
        /// Specifically:
        /// 1. The license path may refer to something outside of the crate itself, e.g. another
        ///    part of a Git repo. The `cargo package` subcommand will copy the license file into
        ///    the root so we need to update the path to reflect this newly copied file.
        /// 2. The package's workspace needs to be set to None. A workspace doesn't make sense
        ///    in the stand-alone context
        /// 3. The package's resolver needs to be set to the workspace's
        /// 4. Any fields inherited from the workspace, need to be hydrated
        fn map_package(
            manifest: &TomlManifest,
            ws: &Workspace<'_>,
            inheritable: &InheritableFields,
            package_root: &Path,
        ) -> CargoResult<Box<TomlProject>> {
            // Clone the existing package/project
            let mut package = manifest
                .package
                .as_ref()
                .or_else(|| manifest.project.as_ref())
                .unwrap()
                .clone();

            // Set the workspace to None
            package.workspace = None;
            // Set the resolver to the workspace's ???
            package.resolver = ws.resolve_behavior().to_manifest();

            // Map the license file to the newly copied one
            let map_license_file = || -> Option<String> {
                package
                    .hydrated_license_file(inheritable)
                    .map(|license_file| {
                        let path = Path::new(license_file);
                        let abs_path = paths::normalize_path(&package_root.join(path));

                        if let Err(_) = abs_path.strip_prefix(package_root) {
                            Some(path.file_name().unwrap().to_str().unwrap().to_string())
                        } else {
                            None
                        }
                    })
                    .flatten()
            };

            // Update the license file
            if let Some(updated_path) = map_license_file() {
                package.license_file = Some(MaybeWorkspace::Defined(updated_path));
            };

            // Hydrate the edition
            package.edition = package
                .hydrated_edition(inheritable)
                .cloned()
                .map(|e| MaybeWorkspace::Defined(e));

            // Hydrate the version
            package.version = package
                .hydrated_version(inheritable)
                .map(|v| MaybeWorkspace::Defined(v.clone()))?;

            // Hydrate the authors
            package.authors = package
                .hydrated_authors(inheritable)
                .cloned()
                .map(|a| MaybeWorkspace::Defined(a));

            // Hydrate the publish flag
            package.publish = package
                .hydrated_publish(inheritable)
                .cloned()
                .map(|p| MaybeWorkspace::Defined(p));

            // Hydrate the description
            package.description = package
                .hydrated_description(inheritable)
                .cloned()
                .map(|d| MaybeWorkspace::Defined(d));

            // Hydrate the homepage
            package.homepage = package
                .hydrated_homepage(inheritable)
                .cloned()
                .map(|h| MaybeWorkspace::Defined(h));

            // Hydrate the documentation
            package.documentation = package
                .hydrated_documentation(inheritable)
                .cloned()
                .map(|d| MaybeWorkspace::Defined(d));

            // Hydrate the readme
            package.readme = package
                .hydrated_readme(inheritable)
                .cloned()
                .map(|r| MaybeWorkspace::Defined(r));

            // Hydrate the keywords
            package.keywords = package
                .hydrated_keywords(inheritable)
                .cloned()
                .map(|k| MaybeWorkspace::Defined(k));

            // Hydrate the categories
            package.categories = package
                .hydrated_categories(inheritable)
                .cloned()
                .map(|c| MaybeWorkspace::Defined(c));

            // Hydrate the license
            package.license = package
                .hydrated_license(inheritable)
                .cloned()
                .map(|l| MaybeWorkspace::Defined(l));

            // Hydrate the license_file
            package.license_file = package
                .hydrated_license_file(inheritable)
                .cloned()
                .map(|l| MaybeWorkspace::Defined(l));

            // Hydrate the repository
            package.repository = package
                .hydrated_repository(inheritable)
                .cloned()
                .map(|r| MaybeWorkspace::Defined(r));

            Ok(package)
        }

        /// The dependencies of our targets need to be mapped like our dependencies
        fn map_targets(
            config: &Config,
            manifest: &TomlManifest,
        ) -> CargoResult<Option<BTreeMap<String, TomlPlatform>>> {
            let map_target = |target: &TomlPlatform| -> CargoResult<TomlPlatform> {
                let all = |_d: &TomlDependency| true;

                let dependencies = map_dependencies(config, target.dependencies.as_ref(), all)?;

                let dev_deps = target
                    .dev_dependencies
                    .as_ref()
                    .or_else(|| target.dev_dependencies2.as_ref());
                let dev_dependencies =
                    map_dependencies(config, dev_deps, TomlDependency::is_version_specified)?;

                let build_deps = target
                    .build_dependencies
                    .as_ref()
                    .or_else(|| target.build_dependencies2.as_ref());
                let build_dependencies = map_dependencies(config, build_deps, all)?;

                Ok(TomlPlatform {
                    dependencies,
                    dev_dependencies,
                    build_dependencies,
                    dev_dependencies2: None,
                    build_dependencies2: None,
                })
            };

            if let Some(targets) = manifest.target.as_ref() {
                let updated_targets = targets
                    .iter()
                    .map(|(name, target)| Ok((name.clone(), map_target(target)?)))
                    .collect::<CargoResult<BTreeMap<String, TomlPlatform>>>()?;

                Ok(Some(updated_targets))
            } else {
                Ok(None)
            }
        }

        // "Utility closure" that doesn't filter anything
        let all = |_d: &TomlDependency| true;

        // Map the package
        let package = Some(map_package(self, ws, inheritable, package_root)?);

        // Hydrate our dependencies from the workspace
        let hydrated_deps = self.hydrated_dependencies(inheritable)?;
        // Map our dependencies to remove path and git components
        let dependencies = map_dependencies(config, hydrated_deps.as_ref(), all)?;
        // Wrap our dependencies into a serializable type
        let dependencies = dependencies.map(|deps| {
            deps.into_iter()
                .map(|(n, dep)| (n, MaybeWorkspace::Defined(dep)))
                .collect()
        });

        // For historical reasons, dev dependencies is either named `dev-dependencies` or
        // `dev_dependencies`, check for both, prefering the first
        let dev_deps = self
            .dev_dependencies
            .as_ref()
            .or_else(|| self.dev_dependencies2.as_ref());
        let dev_dependencies =
            map_dependencies(config, dev_deps, TomlDependency::is_version_specified)?;

        // For historical reasons, dev dependencies is either named `build-dependencies` or
        // `build_dependencies`, check for both, prefering the first.
        let build_deps = self
            .build_dependencies
            .as_ref()
            .or_else(|| self.build_dependencies2.as_ref());
        let build_dependencies = map_dependencies(config, build_deps, all)?;

        // Map the dependencies of our targets like we map the dependencies of ourselves
        let target = map_targets(config, self)?;

        // Hydrate our badges from the workspace, and then wrap them in a serializable type
        let hydrated_badges = self.hydrated_badges(inheritable)?;
        let badges = hydrated_badges.map(|badges| {
            badges.into_iter()
                .map(|(name, badge)| (name, MaybeWorkspace::Defined(badge)))
                .collect()
        });

        // None of these fields need to be modified
        let profile = self.profile.clone();
        let lib = self.lib.clone();
        let bin = self.bin.clone();
        let example = self.example.clone();
        let test = self.test.clone();
        let bench = self.bench.clone();
        let features = self.features.clone();
        let cargo_features = self.cargo_features.clone();

        // We don't want to supply any of these fields
        let project = None;
        let dev_dependencies2 = None;
        let build_dependencies2 = None;
        let replace = None;
        let patch = None;
        let workspace = None;

        return Ok(TomlManifest {
            package,
            project,
            profile,
            lib,
            bin,
            example,
            test,
            bench,
            dependencies,
            dev_dependencies,
            dev_dependencies2,
            build_dependencies,
            build_dependencies2,
            features,
            target,
            replace,
            patch,
            workspace,
            badges,
            cargo_features,
        });
    }

    pub fn to_real_manifest(
        me: &Rc<TomlManifest>,
        source_id: SourceId,
        package_root: &Path,
        config: &Config,
        inheritable: &InheritableFields,
    ) -> CargoResult<(Manifest, Vec<PathBuf>)> {
        let mut nested_paths = vec![];
        let mut warnings = vec![];
        let mut errors = vec![];

        // Parse features first so they will be available when parsing other parts of the TOML.
        let empty = Vec::new();
        let cargo_features = me.cargo_features.as_ref().unwrap_or(&empty);
        let features = Features::new(cargo_features, &mut warnings)?;

        let project = me.project.as_ref().or_else(|| me.package.as_ref());
        let project = project.ok_or_else(|| anyhow!("no `package` section found"))?;

        let package_name = project.name.trim();
        if package_name.is_empty() {
            bail!("package name cannot be an empty string")
        }

        validate_package_name(package_name, "package name", "")?;

        let pkgid = project.to_package_id(source_id, inheritable)?;

        let edition = if let Some(ref edition) = project.hydrated_edition(inheritable) {
            features
                .require(Feature::edition())
                .chain_err(|| "editions are unstable")?;
            edition
                .parse()
                .chain_err(|| "failed to parse the `edition` key")?
        } else {
            Edition::Edition2015
        };

        if let Some(rust_version) = &project.rust_version {
            if features.require(Feature::rust_version()).is_err() {
                let mut msg =
                    "`rust-version` is not supported on this version of Cargo and will be ignored"
                        .to_string();
                if nightly_features_allowed() {
                    msg.push_str(
                        "\n\n\
                        consider adding `cargo-features = [\"rust-version\"]` to the manifest",
                    );
                } else {
                    msg.push_str(
                        "\n\n\
                        this Cargo does not support nightly features, but if you\n\
                        switch to nightly channel you can add\n\
                        `cargo-features = [\"rust-version\"]` to enable this feature",
                    );
                }
                warnings.push(msg);
            }

            let req = match semver::VersionReq::parse(rust_version) {
                // Exclude semver operators like `^` and pre-release identifiers
                Ok(req) if rust_version.chars().all(|c| c.is_ascii_digit() || c == '.') => req,
                _ => bail!("`rust-version` must be a value like \"1.32\""),
            };

            if let Some(first_version) = edition.first_version() {
                let unsupported =
                    semver::Version::new(first_version.major, first_version.minor - 1, 9999);
                if req.matches(&unsupported) {
                    bail!(
                        "rust-version {} is older than first version ({}) required by \
                         the specified edition ({})",
                        rust_version,
                        first_version,
                        edition,
                    )
                }
            }
        }

        if project.metabuild.is_some() {
            features.require(Feature::metabuild())?;
        }

        if project.resolver.is_some()
            || me
                .workspace
                .as_ref()
                .map_or(false, |ws| ws.resolver.is_some())
        {
            features.require(Feature::resolver())?;
        }
        let resolve_behavior = match (
            project.resolver.as_ref(),
            me.workspace.as_ref().and_then(|ws| ws.resolver.as_ref()),
        ) {
            (None, None) => None,
            (Some(s), None) | (None, Some(s)) => Some(ResolveBehavior::from_manifest(s)?),
            (Some(_), Some(_)) => {
                bail!("cannot specify `resolver` field in both `[workspace]` and `[package]`")
            }
        };

        // If we have no lib at all, use the inferred lib, if available.
        // If we have a lib with a path, we're done.
        // If we have a lib with no path, use the inferred lib or else the package name.
        let targets = targets(
            &features,
            me,
            package_name,
            package_root,
            edition,
            &project.build,
            &project.metabuild,
            &mut warnings,
            &mut errors,
        )?;

        if targets.is_empty() {
            debug!("manifest has no build targets");
        }

        if let Err(e) = unique_build_targets(&targets, package_root) {
            warnings.push(format!(
                "file found to be present in multiple \
                 build targets: {}",
                e
            ));
        }

        if let Some(links) = &project.links {
            if !targets.iter().any(|t| t.is_custom_build()) {
                bail!(
                    "package `{}` specifies that it links to `{}` but does not \
                     have a custom build script",
                    pkgid,
                    links
                )
            }
        }

        let mut deps = Vec::new();
        let replace;
        let patch;

        {
            let mut cx = Context {
                pkgid: Some(pkgid),
                deps: &mut deps,
                source_id,
                nested_paths: &mut nested_paths,
                config,
                warnings: &mut warnings,
                features: &features,
                platform: None,
                root: package_root,
            };

            fn process_dependencies(
                cx: &mut Context<'_, '_>,
                new_deps: Option<&BTreeMap<String, TomlDependency>>,
                kind: Option<DepKind>,
            ) -> CargoResult<()> {
                let dependencies = match new_deps {
                    Some(dependencies) => dependencies,
                    None => return Ok(()),
                };
                for (n, v) in dependencies.iter() {
                    let dep = v.to_dependency(n, cx, kind)?;
                    validate_package_name(dep.name_in_toml().as_str(), "dependency name", "")?;
                    cx.deps.push(dep);
                }

                Ok(())
            }

            // Collect the dependencies.
            let deps = me.hydrated_dependencies(inheritable)?;
            process_dependencies(&mut cx, deps.as_ref(), None)?;
            let dev_deps = me
                .dev_dependencies
                .as_ref()
                .or_else(|| me.dev_dependencies2.as_ref());
            process_dependencies(&mut cx, dev_deps, Some(DepKind::Development))?;
            let build_deps = me
                .build_dependencies
                .as_ref()
                .or_else(|| me.build_dependencies2.as_ref());
            process_dependencies(&mut cx, build_deps, Some(DepKind::Build))?;

            for (name, platform) in me.target.iter().flatten() {
                cx.platform = {
                    let platform: Platform = name.parse()?;
                    platform.check_cfg_attributes(&mut cx.warnings);
                    Some(platform)
                };
                process_dependencies(&mut cx, platform.dependencies.as_ref(), None)?;
                let build_deps = platform
                    .build_dependencies
                    .as_ref()
                    .or_else(|| platform.build_dependencies2.as_ref());
                process_dependencies(&mut cx, build_deps, Some(DepKind::Build))?;
                let dev_deps = platform
                    .dev_dependencies
                    .as_ref()
                    .or_else(|| platform.dev_dependencies2.as_ref());
                process_dependencies(&mut cx, dev_deps, Some(DepKind::Development))?;
            }

            replace = me.replace(&mut cx)?;
            patch = me.patch(&mut cx)?;
        }

        {
            let mut names_sources = BTreeMap::new();
            for dep in &deps {
                let name = dep.name_in_toml();
                let prev = names_sources.insert(name.to_string(), dep.source_id());
                if prev.is_some() && prev != Some(dep.source_id()) {
                    bail!(
                        "Dependency '{}' has different source paths depending on the build \
                         target. Each dependency must have a single canonical source path \
                         irrespective of build target.",
                        name
                    );
                }
            }
        }

        let exclude = project.exclude.clone().unwrap_or_default();
        let include = project.include.clone().unwrap_or_default();
        let empty_features = BTreeMap::new();

        let summary = Summary::new(
            config,
            pkgid,
            deps,
            me.features.as_ref().unwrap_or(&empty_features),
            project.links.as_deref(),
        )?;
        let unstable = config.cli_unstable();
        summary.unstable_gate(unstable.namespaced_features, unstable.weak_dep_features)?;

        let badges = me.hydrated_badges(inheritable)?;
        let metadata = ManifestMetadata {
            description: project.hydrated_description(inheritable).cloned(),
            homepage: project.hydrated_homepage(inheritable).cloned(),
            documentation: project.hydrated_documentation(inheritable).cloned(),
            readme: readme_for_project(package_root, project, inheritable),
            authors: project
                .hydrated_authors(inheritable)
                .cloned()
                .unwrap_or_default(),
            license: project.hydrated_license(inheritable).cloned(),
            license_file: project.hydrated_license_file(inheritable).cloned(),
            repository: project.hydrated_repository(inheritable).cloned(),
            keywords: project
                .hydrated_keywords(inheritable)
                .cloned()
                .unwrap_or_default(),
            categories: project
                .hydrated_categories(inheritable)
                .cloned()
                .unwrap_or_default(),
            badges: badges.unwrap_or_default(),
            links: project.links.clone(),
        };

        let workspace_config = match (me.workspace.as_ref(), project.workspace.as_ref()) {
            (Some(config), None) => WorkspaceConfig::Root(
                WorkspaceRootConfig::from_toml_workspace(package_root, &config),
            ),
            (None, root) => WorkspaceConfig::Member {
                root: root.cloned(),
            },
            (Some(..), Some(..)) => bail!(
                "cannot configure both `package.workspace` and \
                 `[workspace]`, only one can be specified"
            ),
        };
        let profiles = me.profile.clone();
        if let Some(profiles) = &profiles {
            profiles.validate(&features, &mut warnings)?;
        }
        let publish = match project.hydrated_publish(inheritable) {
            Some(VecStringOrBool::VecString(ref vecstring)) => Some(vecstring.clone()),
            Some(VecStringOrBool::Bool(false)) => Some(vec![]),
            None | Some(VecStringOrBool::Bool(true)) => None,
        };

        if summary.features().contains_key("default-features") {
            warnings.push(
                "`default-features = [\"..\"]` was found in [features]. \
                 Did you mean to use `default = [\"..\"]`?"
                    .to_string(),
            )
        }

        if let Some(run) = &project.default_run {
            if !targets
                .iter()
                .filter(|t| t.is_bin())
                .any(|t| t.name() == run)
            {
                let suggestion =
                    util::closest_msg(run, targets.iter().filter(|t| t.is_bin()), |t| t.name());
                bail!("default-run target `{}` not found{}", run, suggestion);
            }
        }

        let custom_metadata = project.metadata.clone();
        let mut manifest = Manifest::new(
            summary,
            targets,
            exclude,
            include,
            project.links.clone(),
            metadata,
            custom_metadata,
            profiles,
            publish,
            replace,
            patch,
            workspace_config,
            features,
            edition,
            project.rust_version.clone(),
            project.im_a_teapot,
            project.default_run.clone(),
            Rc::clone(me),
            project.metabuild.clone().map(|sov| sov.0),
            resolve_behavior,
        );
        if project.license_file.is_some() && project.license.is_some() {
            manifest.warnings_mut().add_warning(
                "only one of `license` or \
                 `license-file` is necessary"
                    .to_string(),
            );
        }
        for warning in warnings {
            manifest.warnings_mut().add_warning(warning);
        }
        for error in errors {
            manifest.warnings_mut().add_critical_warning(error);
        }

        manifest.feature_gate()?;

        Ok((manifest, nested_paths))
    }

    fn to_virtual_manifest(
        me: &Rc<TomlManifest>,
        source_id: SourceId,
        root: &Path,
        config: &Config,
    ) -> CargoResult<(VirtualManifest, Vec<PathBuf>)> {
        if me.project.is_some() {
            bail!("this virtual manifest specifies a [project] section, which is not allowed");
        }
        if me.package.is_some() {
            bail!("this virtual manifest specifies a [package] section, which is not allowed");
        }
        if me.lib.is_some() {
            bail!("this virtual manifest specifies a [lib] section, which is not allowed");
        }
        if me.bin.is_some() {
            bail!("this virtual manifest specifies a [[bin]] section, which is not allowed");
        }
        if me.example.is_some() {
            bail!("this virtual manifest specifies a [[example]] section, which is not allowed");
        }
        if me.test.is_some() {
            bail!("this virtual manifest specifies a [[test]] section, which is not allowed");
        }
        if me.bench.is_some() {
            bail!("this virtual manifest specifies a [[bench]] section, which is not allowed");
        }
        if me.dependencies.is_some() {
            bail!("this virtual manifest specifies a [dependencies] section, which is not allowed");
        }
        if me.dev_dependencies.is_some() || me.dev_dependencies2.is_some() {
            bail!("this virtual manifest specifies a [dev-dependencies] section, which is not allowed");
        }
        if me.build_dependencies.is_some() || me.build_dependencies2.is_some() {
            bail!("this virtual manifest specifies a [build-dependencies] section, which is not allowed");
        }
        if me.features.is_some() {
            bail!("this virtual manifest specifies a [features] section, which is not allowed");
        }
        if me.target.is_some() {
            bail!("this virtual manifest specifies a [target] section, which is not allowed");
        }
        if me.badges.is_some() {
            bail!("this virtual manifest specifies a [badges] section, which is not allowed");
        }

        let mut nested_paths = Vec::new();
        let mut warnings = Vec::new();
        let mut deps = Vec::new();
        let empty = Vec::new();
        let cargo_features = me.cargo_features.as_ref().unwrap_or(&empty);
        let features = Features::new(cargo_features, &mut warnings)?;

        let (replace, patch) = {
            let mut cx = Context {
                pkgid: None,
                deps: &mut deps,
                source_id,
                nested_paths: &mut nested_paths,
                config,
                warnings: &mut warnings,
                platform: None,
                features: &features,
                root,
            };
            (me.replace(&mut cx)?, me.patch(&mut cx)?)
        };
        let profiles = me.profile.clone();
        if let Some(profiles) = &profiles {
            profiles.validate(&features, &mut warnings)?;
        }
        if me
            .workspace
            .as_ref()
            .map_or(false, |ws| ws.resolver.is_some())
        {
            features.require(Feature::resolver())?;
        }
        let resolve_behavior = me
            .workspace
            .as_ref()
            .and_then(|ws| ws.resolver.as_deref())
            .map(|r| ResolveBehavior::from_manifest(r))
            .transpose()?;
        let workspace_config = match me.workspace {
            Some(ref config) => {
                WorkspaceConfig::Root(WorkspaceRootConfig::from_toml_workspace(root, &config))
            }
            None => {
                bail!("virtual manifests must be configured with [workspace]");
            }
        };
        Ok((
            VirtualManifest::new(
                replace,
                patch,
                workspace_config,
                profiles,
                features,
                resolve_behavior,
            ),
            nested_paths,
        ))
    }

    fn replace(&self, cx: &mut Context<'_, '_>) -> CargoResult<Vec<(PackageIdSpec, Dependency)>> {
        if self.patch.is_some() && self.replace.is_some() {
            bail!("cannot specify both [replace] and [patch]");
        }
        let mut replace = Vec::new();
        for (spec, replacement) in self.replace.iter().flatten() {
            let mut spec = PackageIdSpec::parse(spec).chain_err(|| {
                format!(
                    "replacements must specify a valid semver \
                     version to replace, but `{}` does not",
                    spec
                )
            })?;
            if spec.url().is_none() {
                spec.set_url(CRATES_IO_INDEX.parse().unwrap());
            }

            if replacement.is_version_specified() {
                bail!(
                    "replacements cannot specify a version \
                     requirement, but found one for `{}`",
                    spec
                );
            }

            let mut dep = replacement.to_dependency(spec.name().as_str(), cx, None)?;
            {
                let version = spec.version().ok_or_else(|| {
                    anyhow!(
                        "replacements must specify a version \
                         to replace, but `{}` does not",
                        spec
                    )
                })?;
                dep.set_version_req(VersionReq::exact(version));
            }
            replace.push((spec, dep));
        }
        Ok(replace)
    }

    fn patch(&self, cx: &mut Context<'_, '_>) -> CargoResult<HashMap<Url, Vec<Dependency>>> {
        let mut patch = HashMap::new();
        for (url, deps) in self.patch.iter().flatten() {
            let url = match &url[..] {
                CRATES_IO_REGISTRY => CRATES_IO_INDEX.parse().unwrap(),
                _ => cx
                    .config
                    .get_registry_index(url)
                    .or_else(|_| url.into_url())
                    .chain_err(|| {
                        format!("[patch] entry `{}` should be a URL or registry name", url)
                    })?,
            };
            patch.insert(
                url,
                deps.iter()
                    .map(|(name, dep)| dep.to_dependency(name, cx, None))
                    .collect::<CargoResult<Vec<_>>>()?,
            );
        }
        Ok(patch)
    }

    /// Returns the path to the build script if one exists for this crate.
    fn maybe_custom_build(
        &self,
        build: &Option<StringOrBool>,
        package_root: &Path,
    ) -> Option<PathBuf> {
        let build_rs = package_root.join("build.rs");
        match *build {
            // Explicitly no build script.
            Some(StringOrBool::Bool(false)) => None,
            Some(StringOrBool::Bool(true)) => Some(build_rs),
            Some(StringOrBool::String(ref s)) => Some(PathBuf::from(s)),
            None => {
                // If there is a `build.rs` file next to the `Cargo.toml`, assume it is
                // a build script.
                if build_rs.is_file() {
                    Some(build_rs)
                } else {
                    None
                }
            }
        }
    }

    pub fn has_profiles(&self) -> bool {
        self.profile.is_some()
    }

    pub fn features(&self) -> Option<&BTreeMap<InternedString, Vec<InternedString>>> {
        self.features.as_ref()
    }
}

/// Returns the name of the README file for a `TomlProject`.
fn readme_for_project(
    package_root: &Path,
    project: &TomlProject,
    inheritable: &InheritableFields,
) -> Option<String> {
    match &project.hydrated_readme(inheritable) {
        None => default_readme_from_package_root(package_root),
        Some(value) => match value {
            StringOrBool::Bool(false) => None,
            StringOrBool::Bool(true) => Some("README.md".to_string()),
            StringOrBool::String(v) => Some(v.clone()),
        },
    }
}

const DEFAULT_README_FILES: [&str; 3] = ["README.md", "README.txt", "README"];

/// Checks if a file with any of the default README file names exists in the package root.
/// If so, returns a `String` representing that name.
fn default_readme_from_package_root(package_root: &Path) -> Option<String> {
    for &readme_filename in DEFAULT_README_FILES.iter() {
        if package_root.join(readme_filename).is_file() {
            return Some(readme_filename.to_string());
        }
    }

    None
}

/// Checks a list of build targets, and ensures the target names are unique within a vector.
/// If not, the name of the offending build target is returned.
fn unique_build_targets(targets: &[Target], package_root: &Path) -> Result<(), String> {
    let mut seen = HashSet::new();
    for target in targets {
        if let TargetSourcePath::Path(path) = target.src_path() {
            let full = package_root.join(path);
            if !seen.insert(full.clone()) {
                return Err(full.display().to_string());
            }
        }
    }
    Ok(())
}

impl TomlDependency {
    fn to_dependency(
        &self,
        name: &str,
        cx: &mut Context<'_, '_>,
        kind: Option<DepKind>,
    ) -> CargoResult<Dependency> {
        match *self {
            TomlDependency::Simple(ref version) => DetailedTomlDependency {
                version: Some(version.clone()),
                ..Default::default()
            }
            .to_dependency(name, cx, kind),
            TomlDependency::Detailed(ref details) => details.to_dependency(name, cx, kind),
        }
    }

    fn is_version_specified(&self) -> bool {
        match self {
            TomlDependency::Detailed(d) => d.version.is_some(),
            TomlDependency::Simple(..) => true,
        }
    }
}

impl DetailedTomlDependency {
    fn to_dependency(
        &self,
        name_in_toml: &str,
        cx: &mut Context<'_, '_>,
        kind: Option<DepKind>,
    ) -> CargoResult<Dependency> {
        if self.version.is_none() && self.path.is_none() && self.git.is_none() {
            let msg = format!(
                "dependency ({}) specified without \
                 providing a local path, Git repository, or \
                 version to use. This will be considered an \
                 error in future versions",
                name_in_toml
            );
            cx.warnings.push(msg);
        }

        if let Some(version) = &self.version {
            if version.contains('+') {
                cx.warnings.push(format!(
                    "version requirement `{}` for dependency `{}` \
                     includes semver metadata which will be ignored, removing the \
                     metadata is recommended to avoid confusion",
                    version, name_in_toml
                ));
            }
        }

        if self.git.is_none() {
            let git_only_keys = [
                (&self.branch, "branch"),
                (&self.tag, "tag"),
                (&self.rev, "rev"),
            ];

            for &(key, key_name) in &git_only_keys {
                if key.is_some() {
                    let msg = format!(
                        "key `{}` is ignored for dependency ({}). \
                         This will be considered an error in future versions",
                        key_name, name_in_toml
                    );
                    cx.warnings.push(msg)
                }
            }
        }

        let new_source_id = match (
            self.git.as_ref(),
            self.path.as_ref(),
            self.registry.as_ref(),
            self.registry_index.as_ref(),
        ) {
            (Some(_), _, Some(_), _) | (Some(_), _, _, Some(_)) => bail!(
                "dependency ({}) specification is ambiguous. \
                 Only one of `git` or `registry` is allowed.",
                name_in_toml
            ),
            (_, _, Some(_), Some(_)) => bail!(
                "dependency ({}) specification is ambiguous. \
                 Only one of `registry` or `registry-index` is allowed.",
                name_in_toml
            ),
            (Some(git), maybe_path, _, _) => {
                if maybe_path.is_some() {
                    let msg = format!(
                        "dependency ({}) specification is ambiguous. \
                         Only one of `git` or `path` is allowed. \
                         This will be considered an error in future versions",
                        name_in_toml
                    );
                    cx.warnings.push(msg)
                }

                let n_details = [&self.branch, &self.tag, &self.rev]
                    .iter()
                    .filter(|d| d.is_some())
                    .count();

                if n_details > 1 {
                    bail!(
                        "dependency ({}) specification is ambiguous. \
                         Only one of `branch`, `tag` or `rev` is allowed.",
                        name_in_toml
                    );
                }

                let reference = self
                    .branch
                    .clone()
                    .map(GitReference::Branch)
                    .or_else(|| self.tag.clone().map(GitReference::Tag))
                    .or_else(|| self.rev.clone().map(GitReference::Rev))
                    .unwrap_or(GitReference::DefaultBranch);
                let loc = git.into_url()?;

                if let Some(fragment) = loc.fragment() {
                    let msg = format!(
                        "URL fragment `#{}` in git URL is ignored for dependency ({}). \
                        If you were trying to specify a specific git revision, \
                        use `rev = \"{}\"` in the dependency declaration.",
                        fragment, name_in_toml, fragment
                    );
                    cx.warnings.push(msg)
                }

                SourceId::for_git(&loc, reference)?
            }
            (None, Some(path), _, _) => {
                cx.nested_paths.push(PathBuf::from(path));
                // If the source ID for the package we're parsing is a path
                // source, then we normalize the path here to get rid of
                // components like `..`.
                //
                // The purpose of this is to get a canonical ID for the package
                // that we're depending on to ensure that builds of this package
                // always end up hashing to the same value no matter where it's
                // built from.
                if cx.source_id.is_path() {
                    let path = cx.root.join(path);
                    let path = util::normalize_path(&path);
                    SourceId::for_path(&path)?
                } else {
                    cx.source_id
                }
            }
            (None, None, Some(registry), None) => SourceId::alt_registry(cx.config, registry)?,
            (None, None, None, Some(registry_index)) => {
                let url = registry_index.into_url()?;
                SourceId::for_registry(&url)?
            }
            (None, None, None, None) => SourceId::crates_io(cx.config)?,
        };

        let (pkg_name, explicit_name_in_toml) = match self.package {
            Some(ref s) => (&s[..], Some(name_in_toml)),
            None => (name_in_toml, None),
        };

        let version = self.version.as_deref();
        let mut dep = match cx.pkgid {
            Some(id) => Dependency::parse(pkg_name, version, new_source_id, id, cx.config)?,
            None => Dependency::parse_no_deprecated(pkg_name, version, new_source_id)?,
        };
        dep.set_features(self.features.iter().flatten())
            .set_default_features(
                self.default_features
                    .or(self.default_features2)
                    .unwrap_or(true),
            )
            .set_optional(self.optional.unwrap_or(false))
            .set_platform(cx.platform.clone());
        if let Some(registry) = &self.registry {
            let registry_id = SourceId::alt_registry(cx.config, registry)?;
            dep.set_registry_id(registry_id);
        }
        if let Some(registry_index) = &self.registry_index {
            let url = registry_index.into_url()?;
            let registry_id = SourceId::for_registry(&url)?;
            dep.set_registry_id(registry_id);
        }

        if let Some(kind) = kind {
            dep.set_kind(kind);
        }
        if let Some(name_in_toml) = explicit_name_in_toml {
            cx.features.require(Feature::rename_dependency())?;
            dep.set_explicit_name_in_toml(name_in_toml);
        }

        if let Some(p) = self.public {
            cx.features.require(Feature::public_dependency())?;

            if dep.kind() != DepKind::Normal {
                bail!("'public' specifier can only be used on regular dependencies, not {:?} dependencies", dep.kind());
            }

            dep.set_public(p);
        }
        Ok(dep)
    }
}

#[derive(Default, Serialize, Deserialize, Debug, Clone)]
struct TomlTarget {
    name: Option<String>,

    // The intention was to only accept `crate-type` here but historical
    // versions of Cargo also accepted `crate_type`, so look for both.
    #[serde(rename = "crate-type")]
    crate_type: Option<Vec<String>>,
    #[serde(rename = "crate_type")]
    crate_type2: Option<Vec<String>>,

    path: Option<PathValue>,
    test: Option<bool>,
    doctest: Option<bool>,
    bench: Option<bool>,
    doc: Option<bool>,
    plugin: Option<bool>,
    #[serde(rename = "proc-macro")]
    proc_macro_raw: Option<bool>,
    #[serde(rename = "proc_macro")]
    proc_macro_raw2: Option<bool>,
    harness: Option<bool>,
    #[serde(rename = "required-features")]
    required_features: Option<Vec<String>>,
    edition: Option<String>,
}

#[derive(Clone)]
struct PathValue(PathBuf);

impl<'de> de::Deserialize<'de> for PathValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        Ok(PathValue(String::deserialize(deserializer)?.into()))
    }
}

impl ser::Serialize for PathValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// Corresponds to a `target` entry, but `TomlTarget` is already used.
#[derive(Serialize, Deserialize, Debug)]
struct TomlPlatform {
    dependencies: Option<BTreeMap<String, TomlDependency>>,
    #[serde(rename = "build-dependencies")]
    build_dependencies: Option<BTreeMap<String, TomlDependency>>,
    #[serde(rename = "build_dependencies")]
    build_dependencies2: Option<BTreeMap<String, TomlDependency>>,
    #[serde(rename = "dev-dependencies")]
    dev_dependencies: Option<BTreeMap<String, TomlDependency>>,
    #[serde(rename = "dev_dependencies")]
    dev_dependencies2: Option<BTreeMap<String, TomlDependency>>,
}

impl TomlTarget {
    fn new() -> TomlTarget {
        TomlTarget::default()
    }

    fn name(&self) -> String {
        match self.name {
            Some(ref name) => name.clone(),
            None => panic!("target name is required"),
        }
    }

    fn proc_macro(&self) -> Option<bool> {
        self.proc_macro_raw.or(self.proc_macro_raw2).or_else(|| {
            if let Some(types) = self.crate_types() {
                if types.contains(&"proc-macro".to_string()) {
                    return Some(true);
                }
            }
            None
        })
    }

    fn crate_types(&self) -> Option<&Vec<String>> {
        self.crate_type
            .as_ref()
            .or_else(|| self.crate_type2.as_ref())
    }
}

impl fmt::Debug for PathValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Represents a field that may be inherited from a parent workspace
#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(untagged)]
pub enum MaybeWorkspace<T> {
    Workspace,
    Defined(T),
}
