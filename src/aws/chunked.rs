// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//! [aws-chunked] encoding of streaming payloads signed with SigV4
//!
//! The body is split into fixed size chunks, each prefixed with a signature that
//! chains from the previous chunk signature, starting from the request signature.
//! This lets a streaming payload be signed without reading it ahead of the upload.
//!
//! [aws-chunked]: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html

use crate::aws::STORE;
use crate::aws::credential::EMPTY_SHA256_HASH;
use crate::client::{CryptoProvider, DigestAlgorithm, crypto_provider};
use crate::util::{hex_digest, hex_encode};
use crate::{PutPayload, PutPayloadError, PutPayloadStream, Result};
use bytes::{Bytes, BytesMut};
use chrono::{DateTime, Utc};
use futures_util::{StreamExt, TryStreamExt};
use std::sync::Arc;

/// The size of every chunk but the last two
///
/// All chunks must have the same size so that the encoded length, which is sent
/// as `content-length` and signed with the request, is known up front.
pub(crate) const CHUNK_SIZE: usize = 64 * 1024;

const CHUNK_ALGORITHM: &str = "AWS4-HMAC-SHA256-PAYLOAD";
const CHUNK_SIGNATURE: &str = ";chunk-signature=";
const SIGNATURE_LEN: usize = 64;

/// Returns the length of the aws-chunked encoding of `content_length` bytes
pub(crate) fn encoded_length(content_length: usize) -> usize {
    let full_chunks = content_length / CHUNK_SIZE;
    let remainder = content_length % CHUNK_SIZE;
    let mut length = full_chunks * frame_length(CHUNK_SIZE) + frame_length(0);
    if remainder != 0 {
        length += frame_length(remainder);
    }
    length
}

/// Returns the encoded length of a chunk of `size` bytes
fn frame_length(size: usize) -> usize {
    format!("{size:x}").len() + CHUNK_SIGNATURE.len() + SIGNATURE_LEN + 2 + size + 2
}

/// Signs the chunks of an aws-chunked body
pub(crate) struct ChunkSigner {
    crypto: Option<Arc<dyn CryptoProvider>>,
    signing_key: Vec<u8>,
    date: String,
    scope: String,
    seed_signature: String,
}

impl std::fmt::Debug for ChunkSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChunkSigner")
            .field("signing_key", &"******")
            .field("date", &self.date)
            .field("scope", &self.scope)
            .field("seed_signature", &self.seed_signature)
            .finish()
    }
}

impl ChunkSigner {
    /// Creates a signer whose first chunk signature chains from `seed_signature`
    ///
    /// `crypto` is the custom [`CryptoProvider`], if any, `signing_key` the SigV4
    /// key derived for `date` and `scope`, and `seed_signature` the signature of
    /// the request carrying the body.
    pub(crate) fn new(
        crypto: Option<Arc<dyn CryptoProvider>>,
        signing_key: Vec<u8>,
        date: DateTime<Utc>,
        scope: String,
        seed_signature: String,
    ) -> Self {
        Self {
            crypto,
            signing_key,
            date: date.format("%Y%m%dT%H%M%SZ").to_string(),
            scope,
            seed_signature,
        }
    }

    /// Returns the replayable aws-chunked encoding of `payload`
    ///
    /// Every replay re-reads `payload` and signs its chunks from the seed signature.
    pub(crate) fn encode(self, payload: PutPayload) -> PutPayload {
        let content_length = payload.content_length();
        let signer = Arc::new(self);
        PutPayload::from_payload_stream(
            move || {
                Encoder {
                    signer: Arc::clone(&signer),
                    source: payload.stream(),
                    source_done: false,
                    buffer: BytesMut::new(),
                    bytes_read: 0,
                    content_length,
                    previous_signature: signer.seed_signature.clone(),
                    finished: false,
                }
                .into_stream()
            },
            encoded_length(content_length),
        )
    }

    /// Signs `chunk`, chaining from `previous_signature`
    fn sign(&self, previous_signature: &str, chunk: &[u8]) -> Result<String> {
        let crypto = crypto_provider(self.crypto.as_deref())?;
        let string_to_sign = format!(
            "{CHUNK_ALGORITHM}\n{}\n{}\n{previous_signature}\n{EMPTY_SHA256_HASH}\n{}",
            self.date,
            self.scope,
            hex_digest(crypto, chunk)?
        );
        let mut ctx = crypto.hmac(DigestAlgorithm::Sha256, &self.signing_key)?;
        ctx.update(string_to_sign.as_bytes());
        Ok(hex_encode(ctx.finish()?))
    }
}

/// The state of one encoding pass over a payload
struct Encoder {
    signer: Arc<ChunkSigner>,
    source: PutPayloadStream,
    source_done: bool,
    buffer: BytesMut,
    bytes_read: usize,
    content_length: usize,
    previous_signature: String,
    finished: bool,
}

impl Encoder {
    fn into_stream(self) -> PutPayloadStream {
        futures_util::stream::try_unfold(self, |mut encoder| async move {
            match encoder.finished {
                true => Ok(None),
                false => Ok(Some((encoder.next_frame().await?, encoder))),
            }
        })
        .boxed()
    }

    /// Reads and encodes the next chunk, the final chunk being empty
    async fn next_frame(&mut self) -> Result<Bytes, PutPayloadError> {
        while !self.source_done && self.buffer.len() < CHUNK_SIZE {
            match self.source.try_next().await? {
                Some(bytes) => {
                    self.bytes_read += bytes.len();
                    self.buffer.extend_from_slice(&bytes);
                }
                None => self.source_done = true,
            }
            if self.bytes_read > self.content_length {
                return Err(self.length_mismatch());
            }
        }

        let chunk = self.buffer.split_to(self.buffer.len().min(CHUNK_SIZE));
        if chunk.is_empty() {
            if self.bytes_read != self.content_length {
                return Err(self.length_mismatch());
            }
            self.finished = true;
        }

        let signature = self.signer.sign(&self.previous_signature, &chunk)?;
        let mut frame = BytesMut::with_capacity(frame_length(chunk.len()));
        frame.extend_from_slice(
            format!("{:x}{CHUNK_SIGNATURE}{signature}\r\n", chunk.len()).as_bytes(),
        );
        frame.extend_from_slice(&chunk);
        frame.extend_from_slice(b"\r\n");
        self.previous_signature = signature;
        Ok(frame.freeze())
    }

    fn length_mismatch(&self) -> PutPayloadError {
        Box::new(crate::Error::Generic {
            store: STORE,
            source: format!(
                "streaming payload does not match its content length of {} bytes, read {}",
                self.content_length, self.bytes_read
            )
            .into(),
        })
    }
}

#[cfg(all(test, any(feature = "aws-lc-rs", feature = "ring")))]
mod tests {
    use super::*;
    use crate::aws::AwsCredential;
    use std::io;

    /// The example of <https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html>
    fn example_signer() -> ChunkSigner {
        let credential = AwsCredential {
            key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            token: None,
        };
        let date = DateTime::parse_from_rfc3339("2013-05-24T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let crypto = crypto_provider(None).unwrap();
        let signing_key = credential
            .signing_key(crypto, date, "us-east-1", "s3")
            .unwrap();
        ChunkSigner::new(
            None,
            signing_key,
            date,
            "20130524/us-east-1/s3/aws4_request".to_string(),
            "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9".to_string(),
        )
    }

    fn payload_of(parts: Vec<Bytes>, content_length: usize) -> PutPayload {
        PutPayload::from_stream(
            move || futures_util::stream::iter(parts.clone().into_iter().map(Ok::<_, io::Error>)),
            content_length,
        )
    }

    /// Splits an encoded body into its chunk signatures and decoded payload
    fn decode(mut body: &[u8]) -> (Vec<String>, Vec<u8>) {
        let mut signatures = vec![];
        let mut payload = vec![];
        loop {
            let header_end = body.windows(2).position(|w| w == b"\r\n").unwrap();
            let header = std::str::from_utf8(&body[..header_end]).unwrap();
            let (size, signature) = header.split_once(CHUNK_SIGNATURE).unwrap();
            let size = usize::from_str_radix(size, 16).unwrap();
            signatures.push(signature.to_string());
            body = &body[header_end + 2..];
            payload.extend_from_slice(&body[..size]);
            assert_eq!(&body[size..size + 2], b"\r\n");
            body = &body[size + 2..];
            if size == 0 {
                assert!(body.is_empty());
                return (signatures, payload);
            }
        }
    }

    #[test]
    fn test_encoded_length() {
        assert_eq!(encoded_length(0), 86);
        assert_eq!(encoded_length(1), 86 + 1 + 17 + 64 + 2 + 1 + 2);
        assert_eq!(
            encoded_length(CHUNK_SIZE),
            86 + 5 + 17 + 64 + 2 + CHUNK_SIZE + 2
        );
        // The example sends 66560 bytes as a 64 KiB and a 1 KiB chunk
        assert_eq!(encoded_length(66560), 66824);
    }

    #[tokio::test]
    async fn test_example_chunk_signatures() {
        // Split the source stream unevenly to exercise re-chunking
        let parts = vec![
            Bytes::from(vec![b'a'; 1000]),
            Bytes::from(vec![b'a'; 65000]),
            Bytes::from(vec![b'a'; 560]),
        ];
        let encoded = example_signer().encode(payload_of(parts, 66560));
        assert_eq!(encoded.content_length(), 66824);

        let body = encoded.bytes().await.unwrap();
        assert_eq!(body.len(), 66824);
        let (signatures, payload) = decode(&body);
        assert_eq!(
            signatures,
            [
                "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
                "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
                "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
            ]
        );
        assert_eq!(payload, vec![b'a'; 66560]);
    }

    #[tokio::test]
    async fn test_replays_from_seed_signature() {
        let parts = vec![Bytes::from(vec![b'b'; 3 * CHUNK_SIZE / 2])];
        let encoded = example_signer().encode(payload_of(parts, 3 * CHUNK_SIZE / 2));

        let first = encoded.bytes().await.unwrap();
        let second = encoded.bytes().await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), encoded.content_length());
    }

    #[tokio::test]
    async fn test_empty_payload() {
        let encoded = example_signer().encode(payload_of(vec![], 0));
        let body = encoded.bytes().await.unwrap();
        assert_eq!(body.len(), encoded_length(0));
        let (signatures, payload) = decode(&body);
        assert_eq!(signatures.len(), 1);
        assert!(payload.is_empty());
    }

    #[tokio::test]
    async fn test_length_mismatch() {
        let short = example_signer().encode(payload_of(vec![Bytes::from_static(b"abc")], 4));
        let err = short.bytes().await.unwrap_err().to_string();
        assert!(err.contains("content length of 4 bytes, read 3"), "{err}");

        let long = example_signer().encode(payload_of(vec![Bytes::from_static(b"abcde")], 4));
        let err = long.bytes().await.unwrap_err().to_string();
        assert!(err.contains("content length of 4 bytes, read 5"), "{err}");
    }
}
