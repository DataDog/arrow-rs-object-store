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

use bytes::Bytes;
use futures_util::Stream;
use futures_util::stream::{BoxStream, StreamExt};
use std::error::Error;
use std::fmt::{Debug, Formatter};
#[cfg(all(feature = "fs", not(target_arch = "wasm32")))]
use std::path::Path;
use std::sync::Arc;

/// The error type yielded by a streaming [`PutPayload`].
pub type PutPayloadError = Box<dyn Error + Send + Sync + 'static>;

/// A stream of bytes used by a streaming [`PutPayload`].
pub type PutPayloadStream = BoxStream<'static, Result<Bytes, PutPayloadError>>;

type StreamFactory = Arc<dyn Fn() -> PutPayloadStream + Send + Sync>;

/// The default chunk size used by [`PutPayload::from_file`].
#[cfg(all(feature = "fs", not(target_arch = "wasm32")))]
pub const DEFAULT_FILE_CHUNK_SIZE: usize = 16 * 1024;

/// A cheaply cloneable payload for a put request.
///
/// A payload can either contain an ordered collection of [`Bytes`], which is
/// fully materialized in memory, or a replayable stream with a known content
/// length, which is read again for every upload attempt. To upload objects too
/// large for a single request, use the multipart API instead:
/// [`ObjectStore::put_multipart_opts`], [`WriteMultipart`], or [`BufWriter`]
///
/// Streaming put support is tracked in
/// [apache/arrow-rs-object-store#281](https://github.com/apache/arrow-rs-object-store/issues/281).
///
/// [`ObjectStore::put_multipart_opts`]: crate::ObjectStore::put_multipart_opts
/// [`WriteMultipart`]: crate::WriteMultipart
/// [`BufWriter`]: crate::buffered::BufWriter
#[derive(Clone)]
pub struct PutPayload(PutPayloadInner);

#[derive(Clone)]
enum PutPayloadInner {
    Bytes(Arc<[Bytes]>),
    Streaming {
        factory: StreamFactory,
        content_length: usize,
    },
}

impl Debug for PutPayload {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            PutPayloadInner::Bytes(bytes) => f.debug_tuple("PutPayload").field(bytes).finish(),
            PutPayloadInner::Streaming { content_length, .. } => f
                .debug_struct("PutPayload")
                .field("streaming", &true)
                .field("content_length", content_length)
                .finish(),
        }
    }
}

impl Default for PutPayload {
    fn default() -> Self {
        Self(PutPayloadInner::Bytes(Arc::new([])))
    }
}

impl PutPayload {
    /// Create a new empty [`PutPayload`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`PutPayload`] from a static slice
    pub fn from_static(s: &'static [u8]) -> Self {
        s.into()
    }

    /// Creates a [`PutPayload`] from a [`Bytes`]
    pub fn from_bytes(s: Bytes) -> Self {
        s.into()
    }

    /// Creates a replayable streaming [`PutPayload`].
    ///
    /// `stream_factory` is invoked for every upload attempt and must return a
    /// new stream starting at the beginning of the payload. The
    /// `content_length` must exactly match the number of bytes yielded.
    pub fn from_stream<F, S, E>(stream_factory: F, content_length: usize) -> Self
    where
        F: Fn() -> S + Send + Sync + 'static,
        S: Stream<Item = Result<Bytes, E>> + Send + 'static,
        E: Error + Send + Sync + 'static,
    {
        let factory = Arc::new(move || {
            stream_factory()
                .map(|result| result.map_err(|e| Box::new(e) as PutPayloadError))
                .boxed()
        });
        Self(PutPayloadInner::Streaming {
            factory,
            content_length,
        })
    }

    /// Creates a replayable streaming [`PutPayload`] from a factory of
    /// [`PutPayloadStream`], see [`Self::from_stream`]
    #[cfg(feature = "aws-base")]
    pub(crate) fn from_payload_stream<F>(stream_factory: F, content_length: usize) -> Self
    where
        F: Fn() -> PutPayloadStream + Send + Sync + 'static,
    {
        Self(PutPayloadInner::Streaming {
            factory: Arc::new(stream_factory),
            content_length,
        })
    }

    /// Creates a replayable streaming payload from a file.
    ///
    /// The file is read in 16 KiB chunks and reopened for every upload attempt.
    /// It must remain available and unchanged until the put request completes.
    #[cfg(all(feature = "fs", not(target_arch = "wasm32")))]
    pub async fn from_file(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::from_file_with_chunk_size(path, DEFAULT_FILE_CHUNK_SIZE).await
    }

    /// Creates a replayable streaming payload from a file using `chunk_size`.
    ///
    /// The file is reopened for every upload attempt. It must remain available
    /// and unchanged until the put request completes.
    ///
    /// # Panics
    ///
    /// Panics if `chunk_size` is zero.
    #[cfg(all(feature = "fs", not(target_arch = "wasm32")))]
    pub async fn from_file_with_chunk_size(
        path: impl AsRef<Path>,
        chunk_size: usize,
    ) -> std::io::Result<Self> {
        assert!(chunk_size > 0, "chunk size must be greater than zero");

        let path = Arc::new(path.as_ref().to_owned());
        let content_length = tokio::fs::metadata(path.as_ref()).await?.len();
        let content_length = usize::try_from(content_length).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file length does not fit in usize",
            )
        })?;

        Ok(Self::from_stream(
            move || {
                let path = Arc::clone(&path);
                futures_util::stream::try_unfold(
                    FileStreamState::Open(path),
                    move |state| async move {
                        use tokio::io::AsyncReadExt;

                        let (mut file, mut buffer) = match state {
                            FileStreamState::Open(path) => (
                                tokio::fs::File::open(path.as_ref()).await?,
                                bytes::BytesMut::new(),
                            ),
                            FileStreamState::Reading(file, buffer) => (file, buffer),
                        };

                        // Reads into uninitialized spare capacity, which a short
                        // read leaves for the next read rather than pinning it
                        buffer.reserve(chunk_size);
                        let read = file
                            .read_buf(&mut bytes::BufMut::limit(&mut buffer, chunk_size))
                            .await?;
                        if read == 0 {
                            return Ok::<_, std::io::Error>(None);
                        }
                        let chunk = buffer.split().freeze();
                        Ok(Some((chunk, FileStreamState::Reading(file, buffer))))
                    },
                )
            },
            content_length,
        ))
    }

    /// Returns the total length of this payload
    pub fn content_length(&self) -> usize {
        match &self.0 {
            PutPayloadInner::Bytes(bytes) => bytes.iter().map(|b| b.len()).sum(),
            PutPayloadInner::Streaming { content_length, .. } => *content_length,
        }
    }

    /// Returns `true` if this is a streaming payload.
    pub fn is_streaming(&self) -> bool {
        matches!(self.0, PutPayloadInner::Streaming { .. })
    }

    /// Returns a new stream over this payload.
    ///
    /// The stream of a streaming payload fails if it yields more or fewer bytes
    /// than its content length.
    pub fn stream(&self) -> PutPayloadStream {
        match &self.0 {
            PutPayloadInner::Bytes(bytes) => {
                futures_util::stream::iter(bytes.as_ref().to_vec().into_iter().map(Ok)).boxed()
            }
            PutPayloadInner::Streaming {
                factory,
                content_length,
            } => validate_content_length(factory(), *content_length),
        }
    }

    /// Collects this payload into a contiguous [`Bytes`].
    pub async fn bytes(&self) -> Result<Bytes, PutPayloadError> {
        match &self.0 {
            PutPayloadInner::Bytes(bytes) => Ok(match bytes.len() {
                0 => Bytes::new(),
                1 => bytes[0].clone(),
                _ => {
                    let mut buffer = Vec::with_capacity(self.content_length());
                    for chunk in bytes.iter() {
                        buffer.extend_from_slice(chunk);
                    }
                    buffer.into()
                }
            }),
            PutPayloadInner::Streaming { content_length, .. } => {
                let mut stream = self.stream();
                let mut buffer = Vec::with_capacity(*content_length);
                while let Some(chunk) = futures_util::TryStreamExt::try_next(&mut stream).await? {
                    buffer.extend_from_slice(&chunk);
                }
                Ok(buffer.into())
            }
        }
    }

    /// Returns an iterator over the [`Bytes`] in this payload
    ///
    /// # Panics
    ///
    /// Panics if this is a streaming payload. Use [`Self::stream`] instead.
    pub fn iter(&self) -> PutPayloadIter<'_> {
        match &self.0 {
            PutPayloadInner::Bytes(bytes) => PutPayloadIter(bytes.iter()),
            PutPayloadInner::Streaming { .. } => {
                panic!("cannot synchronously iterate over a streaming PutPayload")
            }
        }
    }
}

/// Fails `source` if it yields more or fewer than `content_length` bytes
///
/// The chunk completing `content_length` is held back until `source` ends, so
/// that excess data or a trailing error fails the stream. Without this, a
/// consumer that stops after `content_length` bytes, like an HTTP body with a
/// `Content-Length`, would drop them and report success.
fn validate_content_length(source: PutPayloadStream, content_length: usize) -> PutPayloadStream {
    use futures_util::TryStreamExt;

    futures_util::stream::try_unfold(Some((source, 0)), move |state| async move {
        let Some((mut source, mut read)) = state else {
            return Ok(None);
        };
        loop {
            let Some(chunk) = source.try_next().await? else {
                return match read == content_length {
                    true => Ok(None),
                    false => Err(content_length_mismatch(content_length, read)),
                };
            };
            if chunk.is_empty() {
                continue;
            }
            read += chunk.len();
            if read < content_length {
                return Ok(Some((chunk, Some((source, read)))));
            }
            if read > content_length {
                return Err(content_length_mismatch(content_length, read));
            }
            while let Some(excess) = source.try_next().await? {
                if !excess.is_empty() {
                    return Err(content_length_mismatch(content_length, read + excess.len()));
                }
            }
            return Ok(Some((chunk, None)));
        }
    })
    .boxed()
}

/// The error of a streaming payload yielding `read` bytes instead of `content_length`
fn content_length_mismatch(content_length: usize, read: usize) -> PutPayloadError {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "streaming payload does not match its content length of {content_length} bytes, read {read}"
        ),
    ))
}

#[cfg(all(feature = "fs", not(target_arch = "wasm32")))]
enum FileStreamState {
    Open(Arc<std::path::PathBuf>),
    Reading(tokio::fs::File, bytes::BytesMut),
}

impl AsRef<[Bytes]> for PutPayload {
    fn as_ref(&self) -> &[Bytes] {
        match &self.0 {
            PutPayloadInner::Bytes(bytes) => bytes.as_ref(),
            PutPayloadInner::Streaming { .. } => {
                panic!("cannot borrow bytes from a streaming PutPayload")
            }
        }
    }
}

impl<'a> IntoIterator for &'a PutPayload {
    type Item = &'a Bytes;
    type IntoIter = PutPayloadIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for PutPayload {
    type Item = Bytes;
    type IntoIter = PutPayloadIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        PutPayloadIntoIter {
            payload: self,
            idx: 0,
        }
    }
}

/// An iterator over [`PutPayload`]
#[derive(Debug)]
pub struct PutPayloadIter<'a>(std::slice::Iter<'a, Bytes>);

impl<'a> Iterator for PutPayloadIter<'a> {
    type Item = &'a Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

/// An owning iterator of [`PutPayload`]
#[derive(Debug)]
pub struct PutPayloadIntoIter {
    payload: PutPayload,
    idx: usize,
}

impl Iterator for PutPayloadIntoIter {
    type Item = Bytes;

    fn next(&mut self) -> Option<Self::Item> {
        let p = match &self.payload.0 {
            PutPayloadInner::Bytes(bytes) => bytes.get(self.idx)?.clone(),
            PutPayloadInner::Streaming { .. } => {
                panic!("cannot synchronously iterate over a streaming PutPayload")
            }
        };
        self.idx += 1;
        Some(p)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let l = match &self.payload.0 {
            PutPayloadInner::Bytes(bytes) => bytes.len() - self.idx,
            PutPayloadInner::Streaming { .. } => 0,
        };
        (l, Some(l))
    }
}

impl From<Bytes> for PutPayload {
    fn from(value: Bytes) -> Self {
        Self(PutPayloadInner::Bytes(Arc::new([value])))
    }
}

impl From<Vec<u8>> for PutPayload {
    fn from(value: Vec<u8>) -> Self {
        Self(PutPayloadInner::Bytes(Arc::new([value.into()])))
    }
}

impl From<&'static str> for PutPayload {
    fn from(value: &'static str) -> Self {
        Bytes::from(value).into()
    }
}

impl From<&'static [u8]> for PutPayload {
    fn from(value: &'static [u8]) -> Self {
        Bytes::from(value).into()
    }
}

impl From<String> for PutPayload {
    fn from(value: String) -> Self {
        Bytes::from(value).into()
    }
}

impl FromIterator<u8> for PutPayload {
    fn from_iter<T: IntoIterator<Item = u8>>(iter: T) -> Self {
        Bytes::from_iter(iter).into()
    }
}

impl FromIterator<Bytes> for PutPayload {
    fn from_iter<T: IntoIterator<Item = Bytes>>(iter: T) -> Self {
        Self(PutPayloadInner::Bytes(iter.into_iter().collect()))
    }
}

impl From<PutPayload> for Bytes {
    fn from(value: PutPayload) -> Self {
        let bytes = match value.0 {
            PutPayloadInner::Bytes(bytes) => bytes,
            PutPayloadInner::Streaming { .. } => {
                panic!("cannot synchronously collect a streaming PutPayload")
            }
        };
        match bytes.len() {
            0 => Self::new(),
            1 => bytes[0].clone(),
            _ => {
                let mut buf = Vec::with_capacity(bytes.iter().map(|x| x.len()).sum());
                bytes.iter().for_each(|x| buf.extend_from_slice(x));
                buf.into()
            }
        }
    }
}

/// A builder for [`PutPayload`] that avoids reallocating memory
///
/// Data is allocated in fixed blocks, which are flushed to [`Bytes`] once full.
/// Unlike [`Vec`] this avoids needing to repeatedly reallocate blocks of memory,
/// which typically involves copying all the previously written data to a new
/// contiguous memory region.
#[derive(Debug)]
pub struct PutPayloadMut {
    len: usize,
    completed: Vec<Bytes>,
    in_progress: Vec<u8>,
    block_size: usize,
}

impl Default for PutPayloadMut {
    fn default() -> Self {
        Self {
            len: 0,
            completed: vec![],
            in_progress: vec![],

            block_size: 8 * 1024,
        }
    }
}

impl PutPayloadMut {
    /// Create a new [`PutPayloadMut`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures the minimum allocation size
    ///
    /// Defaults to 8KB
    pub fn with_block_size(self, block_size: usize) -> Self {
        Self { block_size, ..self }
    }

    /// Write bytes into this [`PutPayloadMut`]
    ///
    /// If there is an in-progress block, data will be first written to it, flushing
    /// it to [`Bytes`] once full. If data remains to be written, a new block of memory
    /// of at least the configured block size will be allocated, to hold the remaining data.
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        let remaining = self.in_progress.capacity() - self.in_progress.len();
        let to_copy = remaining.min(slice.len());

        self.in_progress.extend_from_slice(&slice[..to_copy]);
        if self.in_progress.capacity() == self.in_progress.len() {
            let new_cap = self.block_size.max(slice.len() - to_copy);
            let completed = std::mem::replace(&mut self.in_progress, Vec::with_capacity(new_cap));
            if !completed.is_empty() {
                self.completed.push(completed.into())
            }
            self.in_progress.extend_from_slice(&slice[to_copy..])
        }
        self.len += slice.len();
    }

    /// Append a [`Bytes`] to this [`PutPayloadMut`] without copying
    ///
    /// This will close any currently buffered block populated by [`Self::extend_from_slice`],
    /// and append `bytes` to this payload without copying.
    pub fn push(&mut self, bytes: Bytes) {
        if !self.in_progress.is_empty() {
            let completed = std::mem::take(&mut self.in_progress);
            self.completed.push(completed.into())
        }
        self.len += bytes.len();
        self.completed.push(bytes);
    }

    /// Returns `true` if this [`PutPayloadMut`] contains no bytes
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the total length of the [`Bytes`] in this payload
    #[inline]
    pub fn content_length(&self) -> usize {
        self.len
    }

    /// Convert into [`PutPayload`]
    pub fn freeze(mut self) -> PutPayload {
        if !self.in_progress.is_empty() {
            let completed = std::mem::take(&mut self.in_progress).into();
            self.completed.push(completed);
        }
        PutPayload(PutPayloadInner::Bytes(self.completed.into()))
    }
}

impl From<PutPayloadMut> for PutPayload {
    fn from(value: PutPayloadMut) -> Self {
        value.freeze()
    }
}

#[cfg(test)]
mod test {
    use crate::PutPayloadMut;
    #[cfg(all(feature = "fs", not(target_arch = "wasm32")))]
    use crate::{DEFAULT_FILE_CHUNK_SIZE, PutPayload};
    #[cfg(all(feature = "fs", not(target_arch = "wasm32")))]
    use futures_util::TryStreamExt;

    #[test]
    fn test_put_payload() {
        let mut chunk = PutPayloadMut::new().with_block_size(23);
        chunk.extend_from_slice(&[1; 16]);
        chunk.extend_from_slice(&[2; 32]);
        chunk.extend_from_slice(&[2; 5]);
        chunk.extend_from_slice(&[2; 21]);
        chunk.extend_from_slice(&[2; 40]);
        chunk.extend_from_slice(&[0; 0]);
        chunk.push("foobar".into());

        let payload = chunk.freeze();
        assert_eq!(payload.content_length(), 120);

        let chunks = payload.as_ref();
        assert_eq!(chunks.len(), 6);

        assert_eq!(chunks[0].len(), 23);
        assert_eq!(chunks[1].len(), 25); // 32 - (23 - 16)
        assert_eq!(chunks[2].len(), 23);
        assert_eq!(chunks[3].len(), 23);
        assert_eq!(chunks[4].len(), 20);
        assert_eq!(chunks[5].len(), 6);
    }

    #[test]
    fn test_content_length() {
        let mut chunk = PutPayloadMut::new();
        chunk.push(vec![0; 23].into());
        assert_eq!(chunk.content_length(), 23);
        chunk.extend_from_slice(&[0; 4]);
        assert_eq!(chunk.content_length(), 27);
        chunk.push(vec![0; 121].into());
        assert_eq!(chunk.content_length(), 148);
        let payload = chunk.freeze();
        assert_eq!(payload.content_length(), 148);
    }

    #[cfg(all(feature = "fs", not(target_arch = "wasm32")))]
    #[tokio::test]
    async fn test_put_payload_from_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("payload");
        let data = vec![42; DEFAULT_FILE_CHUNK_SIZE * 2 + 7];
        tokio::fs::write(&path, &data).await.unwrap();

        let payload = PutPayload::from_file(&path).await.unwrap();
        assert_eq!(payload.content_length(), data.len());

        for _ in 0..2 {
            let chunks: Vec<_> = payload.stream().try_collect().await.unwrap();
            assert_eq!(
                chunks.iter().map(|chunk| chunk.len()).collect::<Vec<_>>(),
                vec![DEFAULT_FILE_CHUNK_SIZE, DEFAULT_FILE_CHUNK_SIZE, 7]
            );
            assert_eq!(chunks.concat(), data);
        }
    }

    #[tokio::test]
    async fn test_bytes_checks_content_length() {
        use bytes::Bytes;

        let payload_of = |data: &'static [u8], content_length| {
            crate::PutPayload::from_stream(
                move || {
                    futures_util::stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(data))])
                },
                content_length,
            )
        };

        assert_eq!(payload_of(b"abcd", 4).bytes().await.unwrap(), b"abcd"[..]);
        let err = payload_of(b"abc", 4).bytes().await.unwrap_err().to_string();
        assert!(err.contains("content length of 4 bytes, read 3"), "{err}");
        let err = payload_of(b"abcde", 4)
            .bytes()
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("content length of 4 bytes, read 5"), "{err}");
    }

    /// The chunk completing the content length must not be yielded before the
    /// source ends, or a consumer stopping at the content length misses the error
    #[tokio::test]
    async fn test_stream_holds_final_chunk_until_source_ends() {
        use bytes::Bytes;
        use futures_util::{StreamExt, TryStreamExt};

        let excess = crate::PutPayload::from_stream(
            || {
                futures_util::stream::iter(
                    ["abc", "def"]
                        .map(|s| Ok::<_, std::io::Error>(Bytes::from_static(s.as_bytes()))),
                )
            },
            3,
        );
        let err = excess
            .stream()
            .next()
            .await
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(err.contains("content length of 3 bytes, read 6"), "{err}");

        let trailing_error = crate::PutPayload::from_stream(
            || {
                futures_util::stream::iter([
                    Ok(Bytes::from_static(b"abc")),
                    Err(std::io::Error::other("trailing failure")),
                ])
            },
            3,
        );
        let err = trailing_error
            .stream()
            .next()
            .await
            .unwrap()
            .unwrap_err()
            .to_string();
        assert!(err.contains("trailing failure"), "{err}");

        let exact = crate::PutPayload::from_stream(
            || {
                futures_util::stream::iter(
                    ["ab", "", "c", ""]
                        .map(|s| Ok::<_, std::io::Error>(Bytes::from_static(s.as_bytes()))),
                )
            },
            3,
        );
        let chunks: Vec<Bytes> = exact.stream().try_collect().await.unwrap();
        assert_eq!(chunks.concat(), b"abc");
    }
}
