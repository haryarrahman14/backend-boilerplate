use std::time::Duration;

use anyhow::Result;
use aws_sdk_s3::{
    Client,
    config::{
        BehaviorVersion, Credentials, Region, RequestChecksumCalculation,
        ResponseChecksumValidation,
    },
    presigning::PresigningConfig,
};

use super::config::Config;

/// S3-compatible object storage (Cloudflare R2 in production, MinIO locally).
#[derive(Clone)]
pub struct Storage {
    client: Client,
    bucket: String,
}

pub const PRESIGN_TTL: Duration = Duration::from_secs(900);

impl Storage {
    pub fn new(cfg: &Config) -> Self {
        let conf = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .endpoint_url(&cfg.s3_endpoint)
            .region(Region::new(cfg.s3_region.clone()))
            .credentials_provider(Credentials::new(
                &cfg.s3_access_key_id,
                &cfg.s3_secret_access_key,
                None,
                None,
                "env",
            ))
            .force_path_style(true)
            // Default flexible checksums would bake a checksum of an empty body into presigned PUTs,
            // and R2 does not support them anyway.
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            .build();
        Self {
            client: Client::from_conf(conf),
            bucket: cfg.s3_bucket.clone(),
        }
    }

    /// Presigned PUT; `Content-Type` and `Content-Length` are signed headers, so the bucket accepts
    /// exactly `size` bytes of exactly that type, before and after `complete`.
    pub async fn presign_put(&self, key: &str, content_type: &str, size: i64) -> Result<String> {
        let req = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .content_type(content_type)
            .content_length(size)
            .presigned(PresigningConfig::expires_in(PRESIGN_TTL)?)
            .await?;
        Ok(req.uri().to_owned())
    }

    pub async fn presign_get(&self, key: &str) -> Result<String> {
        let req = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            // Never rendered inline on the bucket origin.
            .response_content_disposition("attachment")
            .presigned(PresigningConfig::expires_in(PRESIGN_TTL)?)
            .await?;
        Ok(req.uri().to_owned())
    }

    /// Size of the object, or `None` when it does not exist.
    pub async fn head(&self, key: &str) -> Result<Option<i64>> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(out) => Ok(Some(out.content_length().unwrap_or(0))),
            Err(err) => {
                let not_found = err.as_service_error().is_some_and(|e| e.is_not_found())
                    || err
                        .raw_response()
                        .is_some_and(|r| r.status().as_u16() == 404);
                if not_found { Ok(None) } else { Err(err.into()) }
            }
        }
    }

    /// Idempotent: deleting a missing object succeeds.
    pub async fn delete(&self, key: &str) -> Result<()> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await?;
        Ok(())
    }
}
