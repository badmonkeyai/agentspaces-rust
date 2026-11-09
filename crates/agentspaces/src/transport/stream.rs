// Copyright 2026 Bad Monkey, Inc.
// Author: Al Baker
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Length-prefixed framing over any byte stream (SPEC §9: a 4-byte big-endian length, then the
//! frame). A length of zero or above the frame cap cannot be resynchronized and closes the link.
//!
//! Closing a channel ends both of its tasks at once, also when the far end has stopped reading
//! and a write is parked on a full socket: every wait (a read, a queued frame, a write, the
//! final shutdown) is raced against the channel's [`Closer`], so the stream is dropped and the
//! socket closed instead of a task, the socket, and its queued frames outliving the close.

use std::time::Duration;

use agentspaces_wire::limits::MAX_FRAME_BYTES;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};

use super::{CHANNEL_QUEUE, Channel, Closer, FrameReceiver, FrameSender};

/// The longest frame copied behind its length prefix into one write; a longer one is written as
/// the prefix and then the frame itself, so a frame near the cap is never copied.
const COALESCE_BYTES: usize = 64 * 1024;

/// How long the writer waits for the stream's own shutdown (a TLS close_notify) once its queue
/// ends; a far end that stopped reading cannot hold the task longer.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(1);

/// Splits `stream` into a reader task and a writer task and returns the [`Channel`] over them.
/// The tasks end when the stream fails, the remote closes, a bad length arrives, or the
/// channel's [`Closer`] fires; the receiver then yields `None` after any queued frames.
pub fn spawn_stream_channel<S>(
    stream: S,
    scheme: &str,
    remote: &str,
    attested: Option<String>,
) -> Channel
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let (in_tx, in_rx) = mpsc::channel(CHANNEL_QUEUE);
    let (out_tx, out_rx) = mpsc::channel(CHANNEL_QUEUE);
    let (closer, closed) = Closer::new();
    tokio::spawn(read_frames(
        read_half,
        in_tx,
        closed.clone(),
        closer.clone(),
    ));
    tokio::spawn(write_frames(write_half, out_rx, closed, closer.clone()));
    Channel {
        scheme: scheme.to_owned(),
        remote: remote.to_owned(),
        attested,
        sender: FrameSender::new(out_tx, closer.watch()),
        receiver: FrameReceiver::new(in_rx, closer.watch()),
        closer,
    }
}

/// Resolves once the link has been asked to close (or its closer is gone). Looks at the current
/// value first, so a close already seen by an earlier wait still ends this one.
async fn until_closed(closed: &mut watch::Receiver<bool>) {
    loop {
        if *closed.borrow_and_update() {
            return;
        }
        if closed.changed().await.is_err() {
            return;
        }
    }
}

async fn read_frames<R: AsyncRead + Send + Unpin>(
    mut reader: R,
    frames: mpsc::Sender<Vec<u8>>,
    mut closed: watch::Receiver<bool>,
    closer: Closer,
) {
    loop {
        let mut head = [0u8; 4];
        let read = tokio::select! {
            r = reader.read_exact(&mut head) => r,
            () = until_closed(&mut closed) => break,
        };
        if read.is_err() {
            break;
        }
        let length = i32::from_be_bytes(head);
        let Ok(length) = usize::try_from(length) else {
            break;
        };
        if length == 0 || length > MAX_FRAME_BYTES {
            break; // a hostile prefix cannot be resynchronized
        }
        let mut frame = vec![0u8; length];
        let read = tokio::select! {
            r = reader.read_exact(&mut frame) => r,
            () = until_closed(&mut closed) => break,
        };
        if read.is_err() {
            break;
        }
        let queued = tokio::select! {
            sent = frames.send(frame) => sent.is_ok(),
            () = until_closed(&mut closed) => false,
        };
        if !queued {
            break;
        }
    }
    closer.close();
}

/// Writes one frame behind its length prefix: a short frame in one write with its prefix, a
/// long one after it, uncopied.
async fn write_frame<W: AsyncWrite + Send + Unpin>(
    writer: &mut W,
    frame: &[u8],
) -> std::io::Result<()> {
    let length = u32::try_from(frame.len())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let prefix = length.to_be_bytes();
    if frame.len() <= COALESCE_BYTES {
        let mut out = Vec::with_capacity(prefix.len() + frame.len());
        out.extend_from_slice(&prefix);
        out.extend_from_slice(frame);
        writer.write_all(&out).await?;
    } else {
        writer.write_all(&prefix).await?;
        writer.write_all(frame).await?;
    }
    writer.flush().await
}

async fn write_frames<W: AsyncWrite + Send + Unpin>(
    mut writer: W,
    mut frames: mpsc::Receiver<Vec<u8>>,
    mut closed: watch::Receiver<bool>,
    closer: Closer,
) {
    loop {
        let frame = tokio::select! {
            f = frames.recv() => f,
            () = until_closed(&mut closed) => None,
        };
        let Some(frame) = frame else { break };
        let wrote = tokio::select! {
            r = write_frame(&mut writer, &frame) => r.is_ok(),
            // A far end that stopped reading parks the write: the close drops the stream (and
            // the frames still queued) instead of waiting on it.
            () = until_closed(&mut closed) => false,
        };
        if !wrote {
            break;
        }
    }
    if !*closed.borrow() {
        let _ = tokio::time::timeout(SHUTDOWN_WAIT, writer.shutdown()).await;
    }
    closer.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_over_a_duplex_stream_and_a_bad_prefix_closes() {
        let (left, right) = tokio::io::duplex(1 << 16);
        let a = spawn_stream_channel(left, "tcp", "right", None);
        let mut b = spawn_stream_channel(right, "tcp", "left", None);
        a.sender.send(b"hello".to_vec()).await.expect("send");
        a.sender
            .send(vec![7; 70_000])
            .await
            .expect("send a frame larger than one read");
        assert_eq!(b.receiver.recv().await.as_deref(), Some(&b"hello"[..]));
        assert_eq!(b.receiver.recv().await.map(|f| f.len()), Some(70_000));
        a.closer.close();
        assert_eq!(
            b.receiver.recv().await,
            None,
            "the remote closing ends the receiver"
        );

        let (mut raw, other) = tokio::io::duplex(64);
        let mut c = spawn_stream_channel(other, "tcp", "raw", None);
        raw.write_all(&0u32.to_be_bytes()).await.expect("write");
        assert_eq!(
            c.receiver.recv().await,
            None,
            "a zero length prefix closes the link"
        );
    }

    /// A far end that accepts and never reads parks the writer on a full socket. Closing the
    /// channel must still end both tasks and close the socket, not leak the writer (and the socket
    /// and its queued frames) until the far end reads again.
    #[tokio::test]
    async fn closing_a_link_whose_far_end_stopped_reading_ends_its_tasks() {
        use std::time::Duration;
        use tokio::runtime::Handle;
        use tokio::time::{Instant, timeout};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let alive = || Handle::current().metrics().num_alive_tasks();
        let baseline = alive();
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect");
        let (mut held, _) = listener.accept().await.expect("accept");
        let channel = spawn_stream_channel(stream, "tcp", "held", None);
        let mut sent = 0usize;
        loop {
            match timeout(
                Duration::from_millis(200),
                channel.sender.send(vec![7; 60 * 1024]),
            )
            .await
            {
                Ok(Ok(())) => sent += 1,
                Ok(Err(error)) => panic!("the link failed instead of stalling: {error}"),
                Err(_) => break, // the socket buffers and the queue are full: the writer waits
            }
            assert!(sent < 100_000, "the far end never pushed back");
        }
        assert_eq!(alive(), baseline + 2, "the reader and the parked writer");
        channel.closer.close();
        drop(channel);
        let deadline = Instant::now() + Duration::from_secs(1);
        while alive() > baseline {
            assert!(
                Instant::now() < deadline,
                "{} link tasks outlived the close",
                alive() - baseline
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // The far end drains what the socket buffers held, then reads the end of the stream.
        let mut buffer = vec![0u8; 1 << 16];
        let mut drained = 0usize;
        loop {
            match timeout(Duration::from_secs(5), held.read(&mut buffer)).await {
                Ok(Ok(0)) | Ok(Err(_)) => break,
                Ok(Ok(read)) => drained += read,
                Err(_) => panic!("the socket stayed open after the close"),
            }
        }
        assert!(
            drained <= sent * (60 * 1024 + 4),
            "drained {drained} bytes of {sent} frames"
        );
    }
}
