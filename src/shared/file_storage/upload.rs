use axum::{extract::Request, http::header::CONTENT_TYPE};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultipartUploadLimits {
    max_parts: usize,
    max_part_size_bytes: u64,
    max_total_size_bytes: u64,
}

impl MultipartUploadLimits {
    pub fn new(
        max_parts: usize,
        max_part_size_bytes: u64,
        max_total_size_bytes: u64,
    ) -> Result<Self, InvalidMultipartUploadLimits> {
        if max_parts == 0 || max_part_size_bytes == 0 || max_total_size_bytes == 0 {
            return Err(InvalidMultipartUploadLimits::Zero);
        }
        if max_part_size_bytes > max_total_size_bytes {
            return Err(InvalidMultipartUploadLimits::PartExceedsTotal);
        }

        Ok(Self {
            max_parts,
            max_part_size_bytes,
            max_total_size_bytes,
        })
    }

    pub fn single_part(max_size_bytes: u64) -> Result<Self, InvalidMultipartUploadLimits> {
        Self::new(1, max_size_bytes, max_size_bytes)
    }

    pub fn max_parts(self) -> usize {
        self.max_parts
    }

    pub fn max_part_size_bytes(self) -> u64 {
        self.max_part_size_bytes
    }

    pub fn max_total_size_bytes(self) -> u64 {
        self.max_total_size_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadedPart {
    name: String,
    file_name: Option<String>,
    content_type: Option<String>,
    bytes: Vec<u8>,
}

impl UploadedPart {
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Informational client input only. Domain code must never use this value
    /// as a filesystem path without its own validation.
    pub fn file_name(&self) -> Option<&str> {
        self.file_name.as_deref()
    }

    pub fn content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartUpload {
    parts: Vec<UploadedPart>,
    total_size_bytes: u64,
}

impl MultipartUpload {
    pub fn parts(&self) -> &[UploadedPart] {
        &self.parts
    }

    pub fn total_size_bytes(&self) -> u64 {
        self.total_size_bytes
    }

    pub fn into_parts(self) -> Vec<UploadedPart> {
        self.parts
    }
}

/// Collects multipart fields while enforcing limits as chunks arrive. The
/// bytes are never decoded or transcoded. Field names remain transport data;
/// each bounded context decides which names and combinations it accepts.
pub async fn collect_multipart_upload(
    request: Request,
    limits: MultipartUploadLimits,
) -> Result<MultipartUpload, MultipartUploadError> {
    let boundary = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| multer::parse_boundary(value).ok())
        .ok_or(MultipartUploadError::Malformed)?;
    let stream = request.into_body().into_data_stream();
    let mut multipart = multer::Multipart::new(stream, boundary);
    let mut parts = Vec::new();
    let mut total_size_bytes = 0_u64;

    while let Some(mut field) = multipart.next_field().await.map_err(map_parser_error)? {
        if parts.len() == limits.max_parts {
            return Err(MultipartUploadError::TooManyParts {
                maximum: limits.max_parts,
            });
        }

        let name = field
            .name()
            .filter(|value| !value.is_empty())
            .ok_or(MultipartUploadError::MissingPartName)?
            .to_owned();
        let file_name = field.file_name().map(ToOwned::to_owned);
        let content_type = field.content_type().map(ToString::to_string);
        let mut bytes = Vec::new();
        let mut part_size_bytes = 0_u64;

        while let Some(chunk) = field.chunk().await.map_err(map_parser_error)? {
            let chunk_size =
                u64::try_from(chunk.len()).map_err(|_| MultipartUploadError::SizeOverflow)?;
            part_size_bytes = part_size_bytes
                .checked_add(chunk_size)
                .ok_or(MultipartUploadError::SizeOverflow)?;
            total_size_bytes = total_size_bytes
                .checked_add(chunk_size)
                .ok_or(MultipartUploadError::SizeOverflow)?;

            if part_size_bytes > limits.max_part_size_bytes {
                return Err(MultipartUploadError::PartTooLarge {
                    name,
                    maximum: limits.max_part_size_bytes,
                });
            }
            if total_size_bytes > limits.max_total_size_bytes {
                return Err(MultipartUploadError::TotalTooLarge {
                    maximum: limits.max_total_size_bytes,
                });
            }

            bytes.extend_from_slice(&chunk);
        }

        parts.push(UploadedPart {
            name,
            file_name,
            content_type,
            bytes,
        });
    }

    if parts.is_empty() {
        return Err(MultipartUploadError::Empty);
    }

    Ok(MultipartUpload {
        parts,
        total_size_bytes,
    })
}

fn map_parser_error(_error: multer::Error) -> MultipartUploadError {
    MultipartUploadError::Malformed
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum InvalidMultipartUploadLimits {
    #[error("multipart upload limits must be greater than zero")]
    Zero,
    #[error("multipart part limit cannot exceed the total upload limit")]
    PartExceedsTotal,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MultipartUploadError {
    #[error("multipart body is malformed")]
    Malformed,
    #[error("multipart upload must contain at least one part")]
    Empty,
    #[error("multipart part must have a non-empty name")]
    MissingPartName,
    #[error("multipart upload contains more than {maximum} parts")]
    TooManyParts { maximum: usize },
    #[error("multipart part `{name}` exceeds the {maximum}-byte limit")]
    PartTooLarge { name: String, maximum: u64 },
    #[error("multipart upload exceeds the {maximum}-byte total limit")]
    TotalTooLarge { maximum: u64 },
    #[error("multipart upload size overflowed its counter")]
    SizeOverflow,
}

impl MultipartUploadError {
    pub const fn is_too_large(&self) -> bool {
        matches!(
            self,
            Self::TooManyParts { .. } | Self::PartTooLarge { .. } | Self::TotalTooLarge { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        body::Body,
        extract::Request as AxumRequest,
        http::{Request, StatusCode, header::CONTENT_TYPE},
        routing::post,
    };
    use tower::ServiceExt;

    use super::*;

    const BOUNDARY: &str = "lara-shared-upload-boundary";

    fn body(parts: &[(&str, Option<&str>, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (name, file_name, bytes) in parts {
            body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
            let disposition = match file_name {
                Some(file_name) => format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{file_name}\"\r\n"
                ),
                None => format!("Content-Disposition: form-data; name=\"{name}\"\r\n"),
            };
            body.extend_from_slice(disposition.as_bytes());
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        body
    }

    async fn accepts_batch(request: AxumRequest) -> StatusCode {
        let upload =
            collect_multipart_upload(request, MultipartUploadLimits::new(2, 8, 16).unwrap())
                .await
                .unwrap();

        assert_eq!(upload.total_size_bytes(), 6);
        assert_eq!(upload.parts().len(), 2);
        assert_eq!(upload.parts()[0].name(), "file");
        assert_eq!(upload.parts()[0].file_name(), Some("one.map"));
        assert_eq!(
            upload.parts()[0].content_type(),
            Some("application/octet-stream")
        );
        assert_eq!(upload.parts()[0].bytes(), b"one");
        assert_eq!(upload.parts()[1].bytes(), b"two");
        StatusCode::OK
    }

    async fn reports_limit(request: AxumRequest) -> StatusCode {
        let error = collect_multipart_upload(request, MultipartUploadLimits::new(2, 5, 8).unwrap())
            .await
            .unwrap_err();

        match error {
            MultipartUploadError::TooManyParts { .. } => StatusCode::CONFLICT,
            MultipartUploadError::PartTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            MultipartUploadError::TotalTooLarge { .. } => StatusCode::INSUFFICIENT_STORAGE,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    async fn accepts_configured_large_upload(request: AxumRequest) -> StatusCode {
        let upload = collect_multipart_upload(
            request,
            MultipartUploadLimits::single_part(3 * 1024 * 1024).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(upload.total_size_bytes(), 2_100_000);
        StatusCode::OK
    }

    async fn request(path: &str, body: Vec<u8>) -> axum::response::Response {
        Router::new()
            .route("/accept", post(accepts_batch))
            .route("/limit", post(reports_limit))
            .route("/large", post(accepts_configured_large_upload))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header(
                        CONTENT_TYPE,
                        format!("multipart/form-data; boundary={BOUNDARY}"),
                    )
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    #[test]
    fn validates_limits() {
        assert_eq!(
            MultipartUploadLimits::new(0, 1, 1),
            Err(InvalidMultipartUploadLimits::Zero)
        );
        assert_eq!(
            MultipartUploadLimits::new(1, 2, 1),
            Err(InvalidMultipartUploadLimits::PartExceedsTotal)
        );
        assert_eq!(
            MultipartUploadLimits::single_part(4).unwrap(),
            MultipartUploadLimits::new(1, 4, 4).unwrap()
        );
    }

    #[tokio::test]
    async fn preserves_repeated_parts_and_opaque_bytes() {
        let response = request(
            "/accept",
            body(&[
                ("file", Some("one.map"), b"one"),
                ("file", Some("two.map.off"), b"two"),
            ]),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn stops_on_part_total_and_count_limits() {
        let part = request("/limit", body(&[("file", Some("large.map"), b"123456")])).await;
        assert_eq!(part.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let total = request(
            "/limit",
            body(&[
                ("file", Some("one.map"), b"12345"),
                ("file", Some("two.map"), b"6789"),
            ]),
        )
        .await;
        assert_eq!(total.status(), StatusCode::INSUFFICIENT_STORAGE);

        let count = request(
            "/limit",
            body(&[
                ("file", Some("one.map"), b"1"),
                ("file", Some("two.map"), b"2"),
                ("file", Some("three.map"), b"3"),
            ]),
        )
        .await;
        assert_eq!(count.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn rejects_empty_multipart_upload() {
        let response = request("/limit", body(&[])).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn configured_limits_are_not_capped_by_axums_two_megabyte_default() {
        let bytes = vec![b'x'; 2_100_000];
        let response = request(
            "/large",
            body(&[("file", Some("large.map"), bytes.as_slice())]),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
    }
}
