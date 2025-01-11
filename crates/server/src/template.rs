//! Templating for the server, built around handlebars but abstracted away so would be easy to
//! exchange in the future.

use std::num::NonZeroU64;

use handlebars::Handlebars;
use url::Url;

/// [`DownloadPageFields`] contains all of the fields that will be used in the
/// [`../templates/download.hbs`] handlebars template.
#[derive(Debug, serde::Serialize)]
pub struct DownloadPageFields {
    /// The name of the file being downloaded, e.g. `homework.docx`.`
    pub file_name: String,
    /// The full source url where the public key of the user who uploaded this file was acquired.
    /// e.g. `https://www.github.com/josiahbull`, should NOT have a trailing .keys appended.
    pub username_source_url: Url,
    /// The username of the user who uploaded the file, e.g. `josiahbull`.
    pub username: String,
    /// The date the file was uploaded in ms since epoch, e.g. `1620000000000`.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub upload_date: chrono::DateTime<chrono::Utc>,
    /// The date the file will expire in ms since epoch, e.g. `1620000000000`.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub expiry_date: chrono::DateTime<chrono::Utc>,
    /// The size of the file in bytes, e.g. `1024` for a 1kb file.
    pub file_size_bytes: NonZeroU64,
    /// The full URL to download the file, e.g. `https://www.downloads.mysite.com/homework.docx`.
    pub download_url: Url,
    /// The base URL of the site with a trailing slash, e.g. `https://www.downloads.mysite.com`.
    pub base_url: Url,
}

/// A wrapper to handle the templating engine.
#[derive(Debug)]
pub struct Templates {
    /// The handlebars handle.
    handlebars: Handlebars<'static>,
}

impl Templates {
    /// Create a new templating engine with the default configuration.
    pub fn new() -> Self {
        let mut handlebars = Handlebars::new();

        handlebars.set_strict_mode(true);

        handlebars
            .register_template_string("download_page", include_str!("../templates/download.hbs"))
            .expect("Failed to register download_page template");
        Self { handlebars }
    }

    /// Render specifically the download page, with all of the required fields.
    pub fn render_download_page(&self, fields: DownloadPageFields) -> String {
        debug_assert!(
            !fields.username_source_url.as_str().ends_with('/'),
            "username source url should not have trailing slash ="
        );
        debug_assert!(
            !fields.username_source_url.as_str().contains(".keys"),
            "username source url should not end with or contain .keys"
        );
        debug_assert!(
            fields.upload_date < fields.expiry_date,
            "upload date should be before expiry date"
        );
        debug_assert!(
            fields
                .download_url
                .as_str()
                .starts_with(fields.base_url.as_str()),
            "download url should start with base url"
        );
        debug_assert!(
            !fields.download_url.as_str().ends_with('/'),
            "download url should not end with trailing slash"
        );
        debug_assert!(
            fields.base_url.as_str().ends_with('/'),
            "base url should end with trailing slash"
        );

        self.handlebars
            .render("download_page", &fields)
            .expect("Failed to render download_page template")
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use insta::assert_snapshot;

    use super::*;

    #[test]
    fn test_render_download_page() {
        let templates = Templates::new();
        let fields = DownloadPageFields {
            file_name: "homework.docx".to_string(),
            username_source_url: Url::parse("https://www.github.com/josiahbull")
                .expect("hardcoded url to always be valid"),
            username: "josiahbull".to_string(),
            upload_date: chrono::Utc.timestamp_opt(1_620_000_000, 0).unwrap(),
            expiry_date: chrono::Utc.timestamp_opt(1_630_000_000, 0).unwrap(),
            file_size_bytes: NonZeroU64::new(1024).expect("file size should be non-zero"),
            download_url: Url::parse("https://www.downloads.mysite.com/homework.docx")
                .expect("hardcoded url to always be valid"),
            base_url: Url::parse("https://www.downloads.mysite.com/")
                .expect("hardcoded url to always be valid"),
        };
        let rendered = templates.render_download_page(fields);

        assert!(rendered.contains("homework.docx"));
        assert!(rendered.contains("josiahbull"));
        assert!(rendered.contains("1620000000"));
        assert!(rendered.contains("1024"));
        assert!(rendered.contains("https://www.downloads.mysite.com/homework.docx"));

        assert_snapshot!(rendered);
    }
}
