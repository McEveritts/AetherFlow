use once_cell::sync::Lazy;
use regex::Regex;

/// Fixed parser regex matching FileBrowser `search/conditions.go`:
/// `typeRegexp = regexp.MustCompile("type:(\\w+)")` (ASCII `\w` = `[0-9A-Za-z_]`).
static TYPE_REGEXP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"type:([0-9A-Za-z_]+)").expect("valid static type modifier regex"));

/// Type condition parsed from `type:<spec>` modifiers in a search query.
///
/// Multiple conditions in a single query are evaluated with logical OR semantics,
/// matching `search/conditions.go` and `search/search.go`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SearchCondition {
    /// Matches files whose guessed MIME type starts with `"image"` (i.e. `image/*`).
    Image,
    /// Matches files whose guessed MIME type starts with `"audio"` (i.e. `audio/*`).
    /// Triggered by both `type:audio` and `type:music`.
    Audio,
    /// Matches files whose guessed MIME type starts with `"video"` (i.e. `video/*`).
    Video,
    /// Matches entries whose final extension (including the dot) equals `.{ext}` exactly
    /// (`filepath.Ext(path) == "." + extension`).
    Extension(String),
}

impl SearchCondition {
    /// Evaluates whether the condition matches the given filename or path.
    pub(super) fn matches(&self, path_or_name: &str) -> bool {
        let leaf = extract_file_name(path_or_name);
        let Some(ext_without_dot) = extract_ext_without_dot(leaf) else {
            return false;
        };

        match self {
            Self::Image => mime_guess::from_ext(ext_without_dot)
                .iter()
                .any(|m| m.type_() == mime_guess::mime::IMAGE),
            Self::Audio => mime_guess::from_ext(ext_without_dot)
                .iter()
                .any(|m| m.type_() == mime_guess::mime::AUDIO),
            Self::Video => mime_guess::from_ext(ext_without_dot)
                .iter()
                .any(|m| m.type_() == mime_guess::mime::VIDEO),
            Self::Extension(expected) => ext_without_dot == expected,
        }
    }
}

/// Source-pinned McBrowser search query representation following FileBrowser's
/// `search/conditions.go` (`parseSearch`) and `search/search.go` (`Search`).
///
/// Supported modifiers and syntax:
/// - `case:sensitive` / `case:insensitive` (defaults to case-insensitive unless `case:sensitive` is present)
/// - `type:image`, `type:audio`, `type:music`, `type:video`, or `type:<ext>` (exact extension match)
/// - Multiple `type:...` modifiers are combined with OR semantics
/// - Whole remaining query wrapped in `"..."` is treated as a single literal phrase term
/// - Unquoted remaining query is split on `" "` into OR terms matched against the filename only
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(super) struct SearchQuery {
    pub(super) case_sensitive: bool,
    pub(super) conditions: Vec<SearchCondition>,
    pub(super) terms: Vec<String>,
}

impl SearchQuery {
    /// Parses a raw search query string into `SearchQuery` using the exact semantics of
    /// `parseSearch(value string)` in `search/conditions.go`.
    ///
    /// Bounded and deterministic: never compiles user-supplied regular expressions.
    pub(super) fn parse(raw: &str) -> Self {
        let case_sensitive = raw.contains("case:sensitive");

        let value = raw
            .replace("case:insensitive", "")
            .replace("case:sensitive", "");
        let mut value = value.trim().to_string();

        let mut conditions = Vec::new();
        for caps in TYPE_REGEXP.captures_iter(&value) {
            if let Some(m) = caps.get(1) {
                let kind = m.as_str();
                let cond = match kind {
                    "image" => SearchCondition::Image,
                    "audio" | "music" => SearchCondition::Audio,
                    "video" => SearchCondition::Video,
                    ext => SearchCondition::Extension(ext.to_string()),
                };
                conditions.push(cond);
            }
        }

        if !conditions.is_empty() {
            value = TYPE_REGEXP.replace_all(&value, "").into_owned();
        }

        if !case_sensitive {
            value = value.to_lowercase();
        }

        let value = value.trim();
        if value.is_empty() {
            return Self {
                case_sensitive,
                conditions,
                terms: Vec::new(),
            };
        }

        if value.starts_with('"') && value.ends_with('"') {
            let unique = value.strip_prefix('"').unwrap_or(value);
            let unique = unique.strip_suffix('"').unwrap_or(unique);
            return Self {
                case_sensitive,
                conditions,
                terms: vec![unique.to_string()],
            };
        }

        let terms = value.split(' ').map(str::to_string).collect();
        Self {
            case_sensitive,
            conditions,
            terms,
        }
    }

    /// Returns `true` if `file_name` (or the basename of a path) satisfies both:
    /// 1. At least one `type:...` condition (if any conditions are present), and
    /// 2. At least one search term substring in the filename (if any terms are present).
    ///
    /// Note: Matches against the filename component only (never parent directory segments),
    /// matching `_, fileName := path.Split(fPath)` in `search/search.go`.
    pub(super) fn matches(&self, file_name: &str) -> bool {
        self.matches_filename(file_name)
    }

    /// Alias for [`Self::matches`] that explicitly documents filename-only matching semantics.
    pub(super) fn matches_filename(&self, file_name: &str) -> bool {
        let leaf = extract_file_name(file_name);

        if !self.conditions.is_empty() && !self.conditions.iter().any(|cond| cond.matches(leaf)) {
            return false;
        }

        if !self.terms.is_empty() {
            let candidate = if self.case_sensitive {
                leaf.to_string()
            } else {
                leaf.to_lowercase()
            };

            return self.terms.iter().any(|term| candidate.contains(term));
        }

        true
    }
}

/// Extracts the leaf filename component after the last `/`, matching Go's `_, fileName := path.Split(fPath)`.
#[inline]
fn extract_file_name(path_or_name: &str) -> &str {
    match path_or_name.rsplit_once('/') {
        Some((_, name)) => name,
        None => path_or_name,
    }
}

/// Extracts the extension without the leading dot using Go `filepath.Ext` semantics:
/// scans backwards in the final path element for the last `.`.
/// If there is no `.`, returns `None`. If the last `.` is the final character (e.g. `"foo."`),
/// returns `Some("")` (representing `filepath.Ext("foo.") == "."`, which never matches `\w+`).
/// Note: In Go's `filepath.Ext(".bashrc")`, the extension is `".bashrc"`, so `ext_without_dot` is `"bashrc"`.
#[inline]
fn extract_ext_without_dot(leaf_name: &str) -> Option<&str> {
    let dot_idx = leaf_name.rfind('.')?;
    Some(&leaf_name[dot_idx + 1..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_and_whitespace_query() {
        let q = SearchQuery::parse("   ");
        assert!(!q.case_sensitive);
        assert!(q.conditions.is_empty());
        assert!(q.terms.is_empty());
        assert!(q.matches("anything.txt"));
        assert!(q.matches("nested/dir/file"));
    }

    #[test]
    fn case_sensitivity_modifiers_match_go_semantics() {
        let default_q = SearchQuery::parse("ReadMe");
        assert!(!default_q.case_sensitive);
        assert_eq!(default_q.terms, vec!["readme"]);
        assert!(default_q.matches("README.md"));
        assert!(default_q.matches("readme.txt"));

        let insens_q = SearchQuery::parse("case:insensitive FooBar");
        assert!(!insens_q.case_sensitive);
        assert_eq!(insens_q.terms, vec!["foobar"]);
        assert!(insens_q.matches("FOOBAR.rs"));

        let sens_q = SearchQuery::parse("case:sensitive ReadMe");
        assert!(sens_q.case_sensitive);
        assert_eq!(sens_q.terms, vec!["ReadMe"]);
        assert!(sens_q.matches("my_ReadMe.md"));
        assert!(!sens_q.matches("readme.md"));
        assert!(!sens_q.matches("README.md"));

        let both_q = SearchQuery::parse("case:insensitive case:sensitive ExactCase");
        assert!(both_q.case_sensitive);
        assert_eq!(both_q.terms, vec!["ExactCase"]);
        assert!(both_q.matches("ExactCase.txt"));
        assert!(!both_q.matches("exactcase.txt"));
    }

    #[test]
    fn type_media_categories_and_exact_extension_matching() {
        let img_q = SearchQuery::parse("type:image");
        assert_eq!(img_q.conditions, vec![SearchCondition::Image]);
        assert!(img_q.matches("photo.png"));
        assert!(img_q.matches("avatar.JPG"));
        assert!(img_q.matches("icon.webp"));
        assert!(!img_q.matches("song.mp3"));
        assert!(!img_q.matches("no_extension"));

        let audio_q = SearchQuery::parse("type:audio");
        assert_eq!(audio_q.conditions, vec![SearchCondition::Audio]);
        assert!(audio_q.matches("track.mp3"));
        assert!(audio_q.matches("sound.wav"));
        assert!(!audio_q.matches("clip.mp4"));

        let music_q = SearchQuery::parse("type:music");
        assert_eq!(music_q.conditions, vec![SearchCondition::Audio]);
        assert!(music_q.matches("album.flac"));
        assert!(!music_q.matches("photo.jpg"));

        let video_q = SearchQuery::parse("type:video");
        assert_eq!(video_q.conditions, vec![SearchCondition::Video]);
        assert!(video_q.matches("movie.mp4"));
        assert!(video_q.matches("stream.webm"));
        assert!(!video_q.matches("document.pdf"));

        let ext_rs = SearchQuery::parse("type:rs");
        assert_eq!(
            ext_rs.conditions,
            vec![SearchCondition::Extension("rs".to_string())]
        );
        assert!(ext_rs.matches("main.rs"));
        assert!(!ext_rs.matches("main.RS"));
        assert!(!ext_rs.matches("main.rlib"));

        let ext_upper = SearchQuery::parse("type:PDF");
        assert_eq!(
            ext_upper.conditions,
            vec![SearchCondition::Extension("PDF".to_string())]
        );
        assert!(ext_upper.matches("SCAN.PDF"));
        assert!(!ext_upper.matches("scan.pdf"));
    }

    #[test]
    fn multiple_type_conditions_use_or_semantics() {
        let q = SearchQuery::parse("type:image type:video type:md");
        assert_eq!(
            q.conditions,
            vec![
                SearchCondition::Image,
                SearchCondition::Video,
                SearchCondition::Extension("md".to_string()),
            ]
        );
        assert!(q.matches("diagram.svg"));
        assert!(q.matches("demo.mp4"));
        assert!(q.matches("notes.md"));
        assert!(!q.matches("archive.tar.gz"));
    }

    #[test]
    fn unquoted_terms_use_or_semantics_and_quoted_phrase_is_single_term() {
        let or_q = SearchQuery::parse("alpha beta");
        assert_eq!(or_q.terms, vec!["alpha", "beta"]);
        assert!(or_q.matches("my_alpha_file.txt"));
        assert!(or_q.matches("beta_release.zip"));
        assert!(!or_q.matches("gamma.txt"));

        let phrase_q = SearchQuery::parse("type:txt \"hello world\"");
        assert_eq!(
            phrase_q.conditions,
            vec![SearchCondition::Extension("txt".to_string())]
        );
        assert_eq!(phrase_q.terms, vec!["hello world"]);
        assert!(phrase_q.matches("my hello world notes.txt"));
        assert!(!phrase_q.matches("hello.txt"));
        assert!(!phrase_q.matches("world.txt"));
        assert!(!phrase_q.matches("my hello world notes.md"));

        let single_quote = SearchQuery::parse("\"");
        assert_eq!(single_quote.terms, vec![""]);
        assert!(single_quote.matches("any_file.txt"));
    }

    #[test]
    fn matches_filename_only_and_ignores_parent_directories() {
        let q = SearchQuery::parse("secret");
        assert!(q.matches("secret_plan.txt"));
        assert!(q.matches("nested/folder/secret_plan.txt"));
        assert!(!q.matches("secret/folder/public.txt"));
        assert!(!q.matches("projects/secret_dir/index.html"));
    }

    #[test]
    fn does_not_invent_unsupported_modifiers() {
        let dir_q = SearchQuery::parse("type:dir");
        assert_eq!(
            dir_q.conditions,
            vec![SearchCondition::Extension("dir".to_string())]
        );
        assert!(dir_q.matches("custom.dir"));
        assert!(!dir_q.matches("regular_folder"));

        let doc_q = SearchQuery::parse("type:doc");
        assert_eq!(
            doc_q.conditions,
            vec![SearchCondition::Extension("doc".to_string())]
        );
        assert!(doc_q.matches("report.doc"));
        assert!(!doc_q.matches("report.pdf"));

        let archive_q = SearchQuery::parse("type:archive");
        assert_eq!(
            archive_q.conditions,
            vec![SearchCondition::Extension("archive".to_string())]
        );
        assert!(archive_q.matches("backup.archive"));
        assert!(!archive_q.matches("backup.zip"));

        let case_exact_q = SearchQuery::parse("case:exact Report");
        assert!(!case_exact_q.case_sensitive);
        assert_eq!(case_exact_q.terms, vec!["case:exact", "report"]);
    }
}
