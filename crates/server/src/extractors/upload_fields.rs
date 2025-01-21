//! Extractors for fields from a multipart request.

use std::{num::NonZeroU64, time::Duration};

use axum::{
    async_trait,
    extract::{multipart::Field, FromRequest, Multipart, Request},
};

use crate::error::ServerError;

/// Fields extracted from a multipart request.
#[derive(Debug)]
pub struct UploadFields {
    /// Name of the file.
    pub file_name: String,
    /// Size of the file.
    pub file_size: NonZeroU64,
    /// How long the file should be stored for.
    pub expiry: Duration,
    /// The multipart for any further extraction
    pub multipart: Multipart,
}

#[async_trait]
impl<S> FromRequest<S> for UploadFields
where
    S: Send + Sync,
{
    type Rejection = ServerError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let mut multipart =
            Multipart::from_request(req, state)
                .await
                .map_err(|_| ServerError::BadRequest {
                    reason: "Failed to extract multipart data".to_string(),
                })?;

        let (file_name, file_size, expiry) = {
            let file_name: String = parse_field(&mut multipart, "file_name").await?;
            let file_size: NonZeroU64 = parse_field(&mut multipart, "file_size").await?;
            let expiry_secs: NonZeroU64 = parse_field(&mut multipart, "expiry_secs").await?;
            let expiry = std::time::Duration::from_secs(expiry_secs.into());

            (file_name, file_size, expiry)
        };

        Ok(Self {
            file_name,
            file_size,
            expiry,
            multipart,
        })
    }
}

/// Extract a field from the multipart request.
///
/// # Errors
///
/// Returns a `ServerError::BadRequest` if the field is missing or has an unexpected name.
pub async fn extract_field<'a>(
    multipart: &'a mut Multipart,
    field_name: &'static str,
) -> Result<Field<'a>, ServerError> {
    let field = multipart
        .next_field()
        .await?
        .ok_or_else(|| ServerError::BadRequest {
            reason: format!("Missing field: {}", field_name),
        })?;

    let name = field.name().ok_or_else(|| ServerError::BadRequest {
        reason: "Missing field name".to_string(),
    })?;

    if name != field_name {
        return Err(ServerError::BadRequest {
            reason: format!(
                "Unexpected field: expected '{}', got '{}'.",
                field_name, name
            ),
        });
    }

    Ok(field)
}

/// Parse a field from the multipart request.
///
/// # Errors
///
/// Returns a `ServerError::BadRequest` if the field is missing or cannot be parsed.
pub async fn parse_field<T>(
    multipart: &mut Multipart,
    field_name: &'static str,
) -> Result<T, ServerError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Debug,
{
    let value = extract_field(multipart, field_name).await?;
    let value = value.text().await.map_err(|e| ServerError::BadRequest {
        reason: format!("Failed to read field: '{}' because of {:?}", field_name, e),
    })?;
    value.parse().map_err(|e| ServerError::BadRequest {
        reason: format!("Failed to parse field: '{}' becuase of {:?}", field_name, e),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, reason = "tests")]
mod tests {
    use std::fmt::Write;
    use std::time::Duration;

    use axum::body::Body;
    use axum::extract::Multipart;
    use axum::http::Request;
    use indexmap::IndexMap;

    use super::*;

    // Helper function to create a multipart request
    fn create_multipart_request(fields: IndexMap<&str, &str>) -> Request<Body> {
        let boundary = "test_boundary";
        let body_content = fields
            .into_iter()
            .map(|(key, value)| {
                format!(
                    "--{}\r\nContent-Disposition: form-data; name=\"{}\"\r\n\r\n{}\r\n",
                    boundary, key, value
                )
            })
            .collect::<Vec<_>>()
            .join("");
        let mut body_content = body_content;
        write!(&mut body_content, "--{}--\r\n", boundary).unwrap();

        Request::builder()
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={}", boundary),
            )
            .body(Body::from(body_content))
            .unwrap()
    }

    #[tokio::test]
    async fn test_parse_field_valid_field() {
        let mut fields = IndexMap::new();
        fields.insert("file_name", "test_file.txt");
        let req = create_multipart_request(fields);

        let mut multipart = Multipart::from_request(req, &()).await.unwrap();
        let result: Result<String, ServerError> = parse_field(&mut multipart, "file_name").await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test_file.txt");
    }

    #[tokio::test]
    async fn test_parse_field_missing_field() {
        let mut fields = IndexMap::new();
        fields.insert("other_field", "value");
        let req = create_multipart_request(fields);

        let mut multipart = Multipart::from_request(req, &()).await.unwrap();
        let result: Result<String, ServerError> = parse_field(&mut multipart, "file_name").await;

        assert!(result.is_err());
        if let Err(ServerError::BadRequest { reason }) = result {
            assert_eq!(
                reason,
                "Unexpected field: expected 'file_name', got 'other_field'."
            );
        } else {
            panic!("Unexpected error type");
        }
    }

    #[tokio::test]
    async fn test_parse_field_invalid_value() {
        let mut fields = IndexMap::new();
        fields.insert("file_size", "invalid_number");
        let req = create_multipart_request(fields);

        let mut multipart = Multipart::from_request(req, &()).await.unwrap();
        let result: Result<u64, ServerError> = parse_field(&mut multipart, "file_size").await;

        assert!(result.is_err());
        if let Err(ServerError::BadRequest { reason }) = result {
            assert!(reason.contains("Failed to parse field: 'file_size'"));
        } else {
            panic!("Unexpected error type");
        }
    }

    #[tokio::test]
    async fn test_upload_fields_from_request_valid() {
        let mut fields = IndexMap::new();
        fields.insert("file_name", "test_file.txt");
        fields.insert("file_size", "1024");
        fields.insert("expiry_secs", "3600");
        let req = create_multipart_request(fields);

        let state = (); // Dummy state
        let result = UploadFields::from_request(req, &state).await;

        let upload_fields = result.unwrap();
        assert_eq!(upload_fields.file_name, "test_file.txt");
        assert_eq!(upload_fields.file_size, NonZeroU64::new(1024).expect("Non-zero"));
        assert_eq!(upload_fields.expiry, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn test_upload_fields_from_request_missing_fields() {
        let mut fields = IndexMap::new();
        fields.insert("file_name", "test_file.txt");
        let req = create_multipart_request(fields);

        let state = (); // Dummy state
        let result = UploadFields::from_request(req, &state).await;

        assert!(result.is_err());
        if let Err(ServerError::BadRequest { reason }) = result {
            assert!(reason.contains("Missing field"));
        } else {
            panic!("Unexpected error type");
        }
    }
}
