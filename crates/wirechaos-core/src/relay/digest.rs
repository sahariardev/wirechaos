use crate::relay::reader::{Frame, FrameBody};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FrameDigest {
    pub(crate) hash: [u8; 32],
    pub(crate) frame_count: usize,
    pub(crate) byte_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Difference {
    pub(crate) offset: usize,
    pub(crate) frame_type: Option<u8>,
}

pub(crate) fn digest_wire(bytes: &[u8]) -> FrameDigest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    FrameDigest {
        hash: hasher.finalize().into(),
        frame_count: count_frames(bytes),
        byte_count: bytes.len(),
    }
}

pub(crate) fn digest_frames(frames: &[Frame]) -> FrameDigest {
    let mut hasher = Sha256::new();
    let mut frame_count = 0;
    let mut byte_count = 0;

    for frame in frames {
        let wire = encode_frame(frame);
        hasher.update(&wire);
        frame_count += 1;
        byte_count += wire.len();
    }

    FrameDigest {
        hash: hasher.finalize().into(),
        frame_count,
        byte_count,
    }
}

pub(crate) fn first_difference(left: &[u8], right: &[u8]) -> Option<Difference> {
    let offset = left
        .iter()
        .zip(right.iter())
        .position(|(a, b)| a != b)
        .or_else(|| {
            if left.len() != right.len() {
                Some(left.len().min(right.len()))
            } else {
                None
            }
        })?;

    Some(Difference {
        offset,
        frame_type: frame_type_at(left, offset),
    })
}

fn encode_frame(frame: &Frame) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + frame.header.body_len);
    out.push(frame.header.type_byte);
    out.extend_from_slice(&((frame.header.body_len + 4) as u32).to_be_bytes());
    match &frame.body {
        FrameBody::Empty => {}
        FrameBody::Pooled(bytes) => out.extend_from_slice(bytes.as_slice()),
    }
    out
}

fn count_frames(bytes: &[u8]) -> usize {
    let mut count = 0;
    let mut pos = 0;
    while pos + 5 <= bytes.len() {
        let len = u32::from_be_bytes([
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
            bytes[pos + 4],
        ]) as usize;
        if len < 4 || pos + 5 + (len - 4) > bytes.len() {
            break;
        }
        count += 1;
        pos += 5 + (len - 4);
    }
    count
}

fn frame_type_at(bytes: &[u8], offset: usize) -> Option<u8> {
    let mut pos = 0;
    let mut last_type = None;
    while pos + 5 <= bytes.len() {
        let type_byte = bytes[pos];
        let len = u32::from_be_bytes([
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
            bytes[pos + 4],
        ]) as usize;
        if len < 4 {
            break;
        }
        let end = pos + 5 + (len - 4);
        if offset < end {
            last_type = Some(type_byte);
            break;
        }
        pos = end;
    }
    last_type
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::buffer_pool::MultiBufferPool;
    use crate::relay::header::FrameHeader;

    fn frame(type_byte: u8, body: &[u8]) -> Frame {
        if body.is_empty() {
            return Frame {
                header: FrameHeader {
                    type_byte,
                    body_len: 0,
                },
                body: FrameBody::Empty,
            };
        }
        let pool = MultiBufferPool::new(4, 64, 1);
        let mut bytes = pool.get(body.len());
        bytes.copy_from_slice(body);
        Frame {
            header: FrameHeader {
                type_byte,
                body_len: body.len(),
            },
            body: FrameBody::Pooled(bytes),
        }
    }

    fn fixture() -> Vec<Frame> {
        vec![
            frame(b'Q', b"select 1\0"),
            frame(b'T', b"row\0"),
            frame(b'H', b""),
            frame(b'D', b"1\0"),
            frame(b'C', b"SELECT 1\0"),
            frame(b'Z', b"I"),
        ]
    }

    #[test]
    fn framed_digest_matches_reencoded_wire() {
        let frames = fixture();
        let wire: Vec<u8> = frames.iter().flat_map(encode_frame).collect();
        assert_eq!(digest_frames(&frames), digest_wire(&wire));
    }

    #[test]
    fn zero_body_frames_are_in_the_digest() {
        let digest = digest_frames(&fixture());
        assert_eq!(digest.frame_count, 6);
        assert!(digest.byte_count >= 6 * 5);
    }

    #[test]
    fn empty_trace_is_equal() {
        assert_eq!(digest_frames(&[]), digest_wire(&[]));
    }

    #[test]
    fn mismatch_reports_first_difference() {
        let wire: Vec<u8> = fixture().iter().flat_map(encode_frame).collect();
        let mut changed = wire.clone();
        changed[7] ^= 1;
        let difference = first_difference(&wire, &changed).expect("difference");
        assert_eq!(difference.offset, 7);
        assert_eq!(difference.frame_type, Some(b'Q'));
    }
}
