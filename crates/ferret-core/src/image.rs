//! Images the model can be shown: what a record names, how a file is recognised, how big one counts.
//!
//! CONTRACT.
//!
//! `ImageRef { blob, mime, bytes, width, height, name }` is the record's name for an image stored in the
//! blob store. `blob` is the store's lowercase hex id (64 characters, not a handle); `mime` one of
//! `image/png`, `image/jpeg`, `image/gif`, `image/webp`; `bytes` the stored size; `width` and `height`
//! the pixel size read from the header; `name` what the model and the operator call it (the file name
//! of an attachment, the path of a `read`), skipped when absent. The serialized shape is exactly those
//! keys in that order.
//!
//! `detect(bytes)` recognises PNG, JPEG, GIF and WebP by their first bytes, never by an extension, and
//! reads the size from the header with hand-written parsers (PNG `IHDR`; JPEG the first start-of-frame
//! segment; GIF the logical screen; WebP `VP8 `, `VP8L` and `VP8X`). It returns `None` for anything else,
//! for a header cut short, and for a size of zero. `ImageInfo::format` is the name shown to the model
//! (`PNG`, `JPEG`, `GIF`, `WEBP`).
//!
//! `est_tokens` is `min(2000, max(85, ceil(w*h/750)))`. `size_label` writes a byte count in binary units.
//!
//! The sentences the model reads about an image are built here so that the request builder and the
//! tools agree: [`not_shown`] (a model without vision), [`read_header`] (the text of a `read` of an image),
//! [`folded`] (an image's stub), [`too_large`] (a `read` over `max_image_bytes`).
//!
//! Tests required: detection and size for each format (including the three WebP kinds and a JPEG with a
//! marker before its frame), rejection of text, truncated headers and zero sizes, the estimate at its
//! bounds, the serialized shape.

use serde::{Deserialize, Serialize};

/// Most tokens one image is estimated at.
pub const MAX_IMAGE_TOKENS: u64 = 2000;
/// Fewest tokens one image is estimated at.
pub const MIN_IMAGE_TOKENS: u64 = 85;

/// An image kept in the blob store, as a record names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageRef {
    /// The blob store's hex id.
    pub blob: String,
    pub mime: String,
    pub bytes: u64,
    pub width: u32,
    pub height: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ImageRef {
    /// Tokens this image is estimated to take in a request.
    pub fn est_tokens(&self) -> u64 {
        let px = u64::from(self.width).saturating_mul(u64::from(self.height));
        px.div_ceil(750).clamp(MIN_IMAGE_TOKENS, MAX_IMAGE_TOKENS)
    }

    /// What to call it in a sentence: its name, or its blob's first 12 characters.
    pub fn label(&self) -> String {
        match &self.name {
            Some(n) if !n.is_empty() => n.clone(),
            _ => self.blob.chars().take(12).collect(),
        }
    }
}

/// What the first bytes of a file say it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageInfo {
    pub mime: &'static str,
    /// `PNG`, `JPEG`, `GIF` or `WEBP`.
    pub format: &'static str,
    pub width: u32,
    pub height: u32,
}

fn be16(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u32::from(u16::from_be_bytes([*s.first()?, *s.get(1)?])))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([*s.first()?, *s.get(1)?, *s.get(2)?, *s.get(3)?]))
}

fn le16(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u32::from(u16::from_le_bytes([*s.first()?, *s.get(1)?])))
}

fn le24(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(3)?)?;
    Some(u32::from(*s.first()?) | u32::from(*s.get(1)?) << 8 | u32::from(*s.get(2)?) << 16)
}

fn png(b: &[u8]) -> Option<(u32, u32)> {
    if !b.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) || b.get(12..16)? != b"IHDR" {
        return None;
    }
    Some((be32(b, 16)?, be32(b, 20)?))
}

fn gif(b: &[u8]) -> Option<(u32, u32)> {
    if !(b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a")) {
        return None;
    }
    Some((le16(b, 6)?, le16(b, 8)?))
}

fn jpeg(b: &[u8]) -> Option<(u32, u32)> {
    if !b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return None;
    }
    let mut at = 2usize;
    loop {
        // Skip fill bytes, then read a marker.
        while *b.get(at)? != 0xFF {
            at = at.checked_add(1)?;
        }
        while *b.get(at)? == 0xFF {
            at = at.checked_add(1)?;
        }
        let marker = *b.get(at)?;
        at = at.checked_add(1)?;
        match marker {
            // Standalone markers have no length.
            0x01 | 0xD0..=0xD8 => continue,
            // Start of image data or end of image before any frame header.
            0xD9 | 0xDA => return None,
            // Start of frame (not DHT 0xC4, JPG 0xC8, DAC 0xCC).
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF => {
                return Some((be16(b, at.checked_add(5)?)?, be16(b, at.checked_add(3)?)?));
            }
            _ => {
                let len = usize::try_from(be16(b, at)?).ok()?;
                if len < 2 {
                    return None;
                }
                at = at.checked_add(len)?;
            }
        }
    }
}

fn webp(b: &[u8]) -> Option<(u32, u32)> {
    if b.get(..4)? != b"RIFF" || b.get(8..12)? != b"WEBP" {
        return None;
    }
    match b.get(12..16)? {
        b"VP8 " => {
            // Frame tag (3 bytes), start code, then 14-bit sizes.
            if b.get(23..26)? != [0x9D, 0x01, 0x2A] {
                return None;
            }
            Some((le16(b, 26)? & 0x3FFF, le16(b, 28)? & 0x3FFF))
        }
        b"VP8L" => {
            if *b.get(20)? != 0x2F {
                return None;
            }
            let bits = u32::from_le_bytes([*b.get(21)?, *b.get(22)?, *b.get(23)?, *b.get(24)?]);
            Some(((bits & 0x3FFF).checked_add(1)?, ((bits >> 14) & 0x3FFF).checked_add(1)?))
        }
        b"VP8X" => Some((le24(b, 24)?.checked_add(1)?, le24(b, 27)?.checked_add(1)?)),
        _ => None,
    }
}

/// Recognise an image by its first bytes and read its size from the header.
pub fn detect(bytes: &[u8]) -> Option<ImageInfo> {
    let (mime, format, size) = if let Some(s) = png(bytes) {
        ("image/png", "PNG", s)
    } else if let Some(s) = jpeg(bytes) {
        ("image/jpeg", "JPEG", s)
    } else if let Some(s) = gif(bytes) {
        ("image/gif", "GIF", s)
    } else {
        ("image/webp", "WEBP", webp(bytes)?)
    };
    (size.0 > 0 && size.1 > 0).then_some(ImageInfo { mime, format, width: size.0, height: size.1 })
}

/// A size in binary units, as the UI and the attachment list write it (`226.0 KiB`, `3.0 MiB`, `900 B`).
pub fn size_label(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if b < KIB * KIB {
        format!("{:.1} KiB", b / KIB)
    } else if b < KIB * KIB * KIB {
        format!("{:.1} MiB", b / (KIB * KIB))
    } else {
        format!("{:.1} GiB", b / (KIB * KIB * KIB))
    }
}

/// The sentence in place of an image for a model that does not take images.
pub fn not_shown(image: &ImageRef) -> String {
    format!(
        "[image not shown: this model does not take images — {} {}x{} {}]",
        image.label(),
        image.width,
        image.height,
        image.mime
    )
}

/// The sentence in place of an image whose stored bytes could not be read when the request was built.
pub fn unreadable(image: &ImageRef) -> String {
    format!("[image not shown: its stored copy could not be read — {}]", image.label())
}

/// The text of a `read` of an image file.
pub fn read_header(path: &str, info: &ImageInfo, bytes: u64) -> String {
    format!("[read · image · {path} · {}x{} {} · {}]", info.width, info.height, info.format, size_label(bytes))
}

/// The text of a `read` of an image that is over the limit for attaching.
pub fn too_large(path: &str, info: &ImageInfo, bytes: u64, max: u64) -> String {
    format!(
        "[read · image · {path} · {}x{} {} · {}]\nNot attached: the file is over the {} limit for images (`max_image_bytes`).",
        info.width,
        info.height,
        info.format,
        size_label(bytes),
        size_label(max)
    )
}

/// True when the first bytes are the magic of a format `detect` knows (the header may still be beyond them).
pub fn has_magic(head: &[u8]) -> bool {
    head.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A])
        || head.starts_with(&[0xFF, 0xD8, 0xFF])
        || head.starts_with(b"GIF87a")
        || head.starts_with(b"GIF89a")
        || (head.len() >= 12 && head.starts_with(b"RIFF") && head.get(8..12) == Some(b"WEBP".as_slice()))
}

/// The stub line for an image folded out of a tool result.
pub fn folded(image: &ImageRef) -> String {
    format!("[image folded — read {} again to see it]", image.label())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_bytes(w: u32, h: u32) -> Vec<u8> {
        let mut v = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13, b'I', b'H', b'D', b'R'];
        v.extend(w.to_be_bytes());
        v.extend(h.to_be_bytes());
        v.extend([8, 6, 0, 0, 0]);
        v
    }

    fn jpeg_bytes(w: u16, h: u16) -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 16];
        v.extend(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        v.extend([0xFF, 0xDB, 0, 4, 0, 0]);
        v.extend([0xFF, 0xC2, 0, 17, 8]);
        v.extend(h.to_be_bytes());
        v.extend(w.to_be_bytes());
        v.extend([3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
        v
    }

    fn gif_bytes(w: u16, h: u16) -> Vec<u8> {
        let mut v = b"GIF89a".to_vec();
        v.extend(w.to_le_bytes());
        v.extend(h.to_le_bytes());
        v
    }

    fn webp_head(kind: &[u8; 4]) -> Vec<u8> {
        let mut v = b"RIFF".to_vec();
        v.extend([0, 0, 0, 0]);
        v.extend(b"WEBP");
        v.extend(kind);
        v.extend([0, 0, 0, 0]);
        v
    }

    fn webp_lossy(w: u16, h: u16) -> Vec<u8> {
        let mut v = webp_head(b"VP8 ");
        v.extend([0x10, 0x02, 0x00, 0x9D, 0x01, 0x2A]);
        v.extend((w | 0x4000).to_le_bytes());
        v.extend(h.to_le_bytes());
        v
    }

    fn webp_lossless(w: u32, h: u32) -> Vec<u8> {
        let mut v = webp_head(b"VP8L");
        v.push(0x2F);
        v.extend(((w - 1) | ((h - 1) << 14)).to_le_bytes());
        v
    }

    fn webp_extended(w: u32, h: u32) -> Vec<u8> {
        let mut v = webp_head(b"VP8X");
        v.extend([0, 0, 0, 0]);
        v.extend((w - 1).to_le_bytes().get(..3).unwrap_or_default());
        v.extend((h - 1).to_le_bytes().get(..3).unwrap_or_default());
        v
    }

    #[test]
    fn each_format_is_recognised_by_its_bytes_with_its_size() {
        let cases: [(Vec<u8>, &str, &str, u32, u32); 6] = [
            (png_bytes(640, 480), "image/png", "PNG", 640, 480),
            (jpeg_bytes(1920, 1080), "image/jpeg", "JPEG", 1920, 1080),
            (gif_bytes(31, 17), "image/gif", "GIF", 31, 17),
            (webp_lossy(320, 200), "image/webp", "WEBP", 320, 200),
            (webp_lossless(1000, 777), "image/webp", "WEBP", 1000, 777),
            (webp_extended(4000, 3000), "image/webp", "WEBP", 4000, 3000),
        ];
        for (bytes, mime, format, w, h) in cases {
            let info = detect(&bytes).unwrap_or_else(|| panic!("{format} not recognised"));
            assert_eq!((info.mime, info.format, info.width, info.height), (mime, format, w, h));
        }
    }

    #[test]
    fn detection_ignores_everything_but_the_bytes() {
        assert!(detect(b"hello, this is text").is_none());
        assert!(detect(b"").is_none());
        assert!(detect(b"<svg xmlns='http://www.w3.org/2000/svg'/>").is_none());
        assert!(detect(&png_bytes(0, 10)).is_none(), "a zero size is not an image");
        assert!(detect(&png_bytes(10, 0)).is_none());
        assert!(detect(png_bytes(5, 5).get(..20).unwrap_or_default()).is_none(), "a cut header");
        assert!(detect(jpeg_bytes(5, 5).get(..30).unwrap_or_default()).is_none());
        assert!(detect(&gif_bytes(5, 5)[..8]).is_none());
        assert!(detect(&[0xFF, 0xD8, 0xFF]).is_none(), "a JPEG with no frame header");
        let mut not_ihdr = png_bytes(5, 5);
        not_ihdr[12] = b'X';
        assert!(detect(&not_ihdr).is_none());
    }

    #[test]
    fn a_jpeg_whose_marker_length_is_nonsense_does_not_loop_or_panic() {
        let v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 0, 1, 2, 3];
        assert!(detect(&v).is_none());
        let v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0xFF, 0xFF];
        assert!(detect(&v).is_none());
    }

    #[test]
    fn the_estimate_is_bounded() {
        let at = |w, h| ImageRef {
            blob: "a".repeat(64),
            mime: "image/png".into(),
            bytes: 1,
            width: w,
            height: h,
            name: None,
        };
        assert_eq!(at(1, 1).est_tokens(), 85);
        assert_eq!(at(150, 150).est_tokens(), 85);
        assert_eq!(at(1000, 1000).est_tokens(), 1334);
        assert_eq!(at(4000, 4000).est_tokens(), 2000);
        assert_eq!(at(u32::MAX, u32::MAX).est_tokens(), 2000);
    }

    #[test]
    fn the_serialized_shape_is_fixed() {
        let r = ImageRef {
            blob: "ab".repeat(32),
            mime: "image/png".into(),
            bytes: 12,
            width: 3,
            height: 4,
            name: Some("a.png".into()),
        };
        let s = serde_json::to_string(&r).unwrap_or_default();
        assert_eq!(
            s,
            format!(
                "{{\"blob\":\"{}\",\"mime\":\"image/png\",\"bytes\":12,\"width\":3,\"height\":4,\"name\":\"a.png\"}}",
                "ab".repeat(32)
            )
        );
        let nameless = ImageRef { name: None, ..r };
        assert!(!serde_json::to_string(&nameless).unwrap_or_default().contains("name"));
    }

    #[test]
    fn sizes_and_sentences() {
        assert_eq!(size_label(900), "900 B");
        assert_eq!(size_label(2048), "2.0 KiB");
        assert_eq!(size_label(3 * 1024 * 1024), "3.0 MiB");
        let info = ImageInfo { mime: "image/png", format: "PNG", width: 640, height: 480 };
        assert_eq!(read_header("/w/a.png", &info, 2048), "[read · image · /w/a.png · 640x480 PNG · 2.0 KiB]");
    }
}
