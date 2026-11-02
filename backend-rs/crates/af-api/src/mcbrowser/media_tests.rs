use super::*;
use image::{DynamicImage, GenericImageView, ImageFormat, Rgba, RgbaImage};
use rand::Rng;
use std::fs;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let token: u128 = rng.gen();
            let path = std::env::temp_dir().join(format!("af-media-test-{token:032x}"));
            if fs::create_dir(&path).is_ok() {
                return Self { path };
            }
        }
        panic!("failed to allocate test temp dir");
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn png_crc32(chunk_type: &[u8; 4], data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in chunk_type.iter().chain(data.iter()) {
        crc ^= b as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xedb8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn write_test_png_chunk(out: &mut Vec<u8>, chunk_type: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(chunk_type);
    out.extend_from_slice(data);
    out.extend_from_slice(&png_crc32(chunk_type, data).to_be_bytes());
}

fn build_test_png_header_only(width: u32, height: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
    let mut ihdr = [0u8; 13];
    ihdr[0..4].copy_from_slice(&width.to_be_bytes());
    ihdr[4..8].copy_from_slice(&height.to_be_bytes());
    ihdr[8] = 8;
    ihdr[9] = 6;
    write_test_png_chunk(&mut out, b"IHDR", &ihdr);
    write_test_png_chunk(&mut out, b"IEND", &[]);
    out
}

fn build_real_png(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
    let img = RgbaImage::from_pixel(width, height, Rgba(color));
    encode_png_image(&DynamicImage::ImageRgba8(img)).unwrap()
}

fn build_real_jpeg(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
    let img = RgbaImage::from_pixel(width, height, Rgba(color));
    encode_jpeg_image(&DynamicImage::ImageRgba8(img), 95).unwrap()
}

fn build_real_bmp(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
    let img = DynamicImage::ImageRgba8(RgbaImage::from_pixel(width, height, Rgba(color)));
    let mut out = Vec::new();
    img.write_to(&mut Cursor::new(&mut out), ImageFormat::Bmp)
        .unwrap();
    out
}

fn build_jpeg_with_exif_thumbnail(
    main_w: u32,
    main_h: u32,
    main_color: [u8; 4],
    thumb_jpeg: &[u8],
) -> Vec<u8> {
    let mut tiff = Vec::new();
    // Little-endian TIFF header: "II*\0", IFD0 at offset 8
    tiff.extend_from_slice(b"II*\x00");
    tiff.extend_from_slice(&8u32.to_le_bytes());
    // IFD0: 0 entries, next IFD (IFD1) at offset 14
    tiff.extend_from_slice(&0u16.to_le_bytes());
    tiff.extend_from_slice(&14u32.to_le_bytes());
    // IFD1 at offset 14: 2 entries (0x0201 offset, 0x0202 length) + 4-byte next IFD (0)
    // IFD1 size = 2 + 2*12 + 4 = 30 bytes -> thumb data starts at offset 44
    let thumb_offset = 44u32;
    let thumb_len = thumb_jpeg.len() as u32;
    tiff.extend_from_slice(&2u16.to_le_bytes());
    // Entry 1: tag 0x0201, type 4 (LONG), count 1, value = thumb_offset
    tiff.extend_from_slice(&0x0201u16.to_le_bytes());
    tiff.extend_from_slice(&4u16.to_le_bytes());
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&thumb_offset.to_le_bytes());
    // Entry 2: tag 0x0202, type 4 (LONG), count 1, value = thumb_len
    tiff.extend_from_slice(&0x0202u16.to_le_bytes());
    tiff.extend_from_slice(&4u16.to_le_bytes());
    tiff.extend_from_slice(&1u32.to_le_bytes());
    tiff.extend_from_slice(&thumb_len.to_le_bytes());
    // Next IFD = 0
    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff.extend_from_slice(thumb_jpeg);

    let mut app1 = Vec::new();
    app1.extend_from_slice(b"Exif\x00\x00");
    app1.extend_from_slice(&tiff);
    let app1_seg_len = (app1.len() + 2) as u16;

    let base_jpeg = build_real_jpeg(main_w, main_h, main_color);
    let mut jpeg = Vec::with_capacity(base_jpeg.len() + app1.len() + 4);
    jpeg.extend_from_slice(b"\xff\xd8");
    jpeg.extend_from_slice(b"\xff\xe1");
    jpeg.extend_from_slice(&app1_seg_len.to_be_bytes());
    jpeg.extend_from_slice(&app1);
    jpeg.extend_from_slice(&base_jpeg[2..]);
    jpeg
}

fn build_test_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut writer = ZipWriter::new(&mut cursor);
        for &(name, content, deflate) in entries {
            let options = SimpleFileOptions::default().compression_method(if deflate {
                CompressionMethod::Deflated
            } else {
                CompressionMethod::Stored
            });
            writer.start_file(name, options).unwrap();
            writer.write_all(content).unwrap();
        }
        writer.finish().unwrap();
    }
    cursor.into_inner()
}

#[test]
fn media_requires_allowlisted_extension_and_matching_signature() {
    assert_eq!(
        media_type("photo.PNG", b"\x89PNG\r\n\x1a\n"),
        Some("image/png")
    );
    assert_eq!(
        media_type("document.pdf", b"%PDF-1.7"),
        Some("application/pdf")
    );
    assert_eq!(
        media_type("book.epub", b"PK\x03\x04\x14\x00\x00\x00"),
        Some("application/epub+zip")
    );
    assert_eq!(
        media_type(
            "bitmap.bmp",
            &[
                b'B', b'M', 0, 0, 0, 0, 0, 0, 0, 0, 54, 0, 0, 0, 40, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0,
                0
            ]
        ),
        Some("image/bmp")
    );
    assert_eq!(
        media_type("scan.tiff", b"II*\x00\x08\x00\x00\x00"),
        Some("image/tiff")
    );
    assert_eq!(media_type("photo.png", b"<script>alert(1)</script>"), None);
    assert_eq!(media_type("photo.svg", b"<svg onload='alert(1)'/>"), None);
    assert_eq!(media_type("photo.html", b"\x89PNG\r\n\x1a\n"), None);
    assert_eq!(
        media_type("clip.mp4", b"\0\0\0\x18ftypisom"),
        Some("video/mp4")
    );
    assert_eq!(media_type("clip.mp4", b"ftyp"), None);
    assert_eq!(
        media_type("audio.wav", b"RIFF\0\0\0\0WAVE"),
        Some("audio/wav")
    );
    assert_eq!(media_type("audio.wav", b"RIFF\0\0\0\0WEBP"), None);
}

#[test]
fn inspects_image_dimensions_and_enforces_10000x10000_oom_guard() {
    let png_800x600 = build_test_png_header_only(800, 600);
    assert_eq!(
        inspect_image_dimensions("banner.png", &png_800x600).unwrap(),
        ImageResolution {
            width: 800,
            height: 600
        }
    );

    let mut gif_320x240 = b"GIF89a".to_vec();
    gif_320x240.extend_from_slice(&320u16.to_le_bytes());
    gif_320x240.extend_from_slice(&240u16.to_le_bytes());
    assert_eq!(
        inspect_image_dimensions("anim.gif", &gif_320x240).unwrap(),
        ImageResolution {
            width: 320,
            height: 240
        }
    );

    let bomb_png = build_test_png_header_only(20_000, 20_000);
    let bomb_dims = inspect_image_dimensions("huge_bomb.png", &bomb_png).unwrap();
    assert_eq!(
        bomb_dims,
        ImageResolution {
            width: 20_000,
            height: 20_000
        }
    );
    assert!(matches!(
        validate_image_dimensions_for_thumbnail(bomb_dims),
        Err(McBrowserError::PayloadTooLarge(_))
    ));
    assert!(matches!(
        generate_bounded_thumbnail("huge_bomb.png", &bomb_png, PreviewSize::Thumb),
        Err(McBrowserError::PayloadTooLarge(_))
    ));
}

#[test]
fn generates_bounded_256_fill_and_1080_fit_thumbnails_and_uses_exif_fast_path() {
    // 1. Real PNG 400x200 -> 256x256 thumb JPEG & 400x200 (<=1080) fit PNG
    let png_bytes = build_real_png(400, 200, [40, 120, 220, 255]);
    let (thumb_bytes, thumb_mime, thumb_dims) =
        generate_bounded_thumbnail("photo.png", &png_bytes, PreviewSize::Thumb).unwrap();
    assert_eq!(thumb_mime, "image/jpeg");
    assert_eq!(
        thumb_dims,
        ImageResolution {
            width: 256,
            height: 256
        }
    );
    assert_eq!(
        inspect_image_dimensions("thumb.jpg", &thumb_bytes).unwrap(),
        ImageResolution {
            width: 256,
            height: 256
        }
    );

    // 2. Real BMP 1600x1200 -> 1080x810 Fit
    let bmp_bytes = build_real_bmp(1600, 1200, [200, 80, 50, 255]);
    let (big_bytes, big_mime, big_dims) =
        generate_bounded_thumbnail("poster.bmp", &bmp_bytes, PreviewSize::Big).unwrap();
    assert_eq!(big_mime, "image/jpeg");
    assert_eq!(
        big_dims,
        ImageResolution {
            width: 1080,
            height: 810
        }
    );
    assert_eq!(
        inspect_image_dimensions("poster.jpg", &big_bytes).unwrap(),
        ImageResolution {
            width: 1080,
            height: 810
        }
    );

    // 3. JPEG with embedded EXIF 160x120 thumbnail -> fast-path returns exact embedded JPEG
    let embedded_jpeg = build_real_jpeg(160, 120, [30, 210, 90, 255]);
    let camera_jpeg = build_jpeg_with_exif_thumbnail(1200, 900, [220, 40, 40, 255], &embedded_jpeg);

    let (fast_bytes, fast_mime, fast_dims) =
        generate_bounded_thumbnail("camera.jpg", &camera_jpeg, PreviewSize::Thumb).unwrap();
    assert_eq!(fast_mime, "image/jpeg");
    assert_eq!(
        fast_dims,
        ImageResolution {
            width: 160,
            height: 120
        }
    );
    assert_eq!(fast_bytes, embedded_jpeg);
}

#[test]
fn red_jpeg_and_png_yield_red_thumbnail_pixels() {
    let red_rgba = [240u8, 20u8, 30u8, 255u8];
    let red_jpeg = build_real_jpeg(640, 480, red_rgba);
    let red_png = build_real_png(640, 480, red_rgba);

    let assert_decoded_pixels_are_red = |bytes: &[u8], expected_w: u32, expected_h: u32| {
        let decoded = image::load_from_memory(bytes)
            .expect("thumbnail output must decode as a valid raster image");
        assert_eq!(decoded.dimensions(), (expected_w, expected_h));

        let sample_points = [
            (0, 0),
            (expected_w / 2, expected_h / 2),
            (expected_w - 1, expected_h - 1),
            (expected_w / 4, expected_h * 3 / 4),
        ];
        for (x, y) in sample_points {
            let px = decoded.get_pixel(x, y);
            let [r, g, b, _a] = px.0;
            assert!(
                r >= 200 && g <= 60 && b <= 60,
                "expected red pixel at ({x}, {y}), got RGBA({r}, {g}, {b}, {})",
                px.0[3]
            );
        }
    };

    let (jpeg_thumb, jpeg_thumb_mime, jpeg_thumb_dims) =
        generate_bounded_thumbnail("crimson.jpg", &red_jpeg, PreviewSize::Thumb).unwrap();
    assert_eq!(jpeg_thumb_mime, "image/jpeg");
    assert_eq!(
        jpeg_thumb_dims,
        ImageResolution {
            width: 256,
            height: 256
        }
    );
    assert_decoded_pixels_are_red(&jpeg_thumb, 256, 256);

    let (jpeg_big, jpeg_big_mime, jpeg_big_dims) =
        generate_bounded_thumbnail("crimson.jpg", &red_jpeg, PreviewSize::Big).unwrap();
    assert_eq!(jpeg_big_mime, "image/jpeg");
    assert_eq!(
        jpeg_big_dims,
        ImageResolution {
            width: 640,
            height: 480
        }
    );
    assert_decoded_pixels_are_red(&jpeg_big, 640, 480);

    let (png_thumb, png_thumb_mime, png_thumb_dims) =
        generate_bounded_thumbnail("crimson.png", &red_png, PreviewSize::Thumb).unwrap();
    assert_eq!(png_thumb_mime, "image/jpeg");
    assert_eq!(
        png_thumb_dims,
        ImageResolution {
            width: 256,
            height: 256
        }
    );
    assert_decoded_pixels_are_red(&png_thumb, 256, 256);

    let (png_big, png_big_mime, png_big_dims) =
        generate_bounded_thumbnail("crimson.png", &red_png, PreviewSize::Big).unwrap();
    assert_eq!(png_big_mime, "image/png");
    assert_eq!(
        png_big_dims,
        ImageResolution {
            width: 640,
            height: 480
        }
    );
    assert_decoded_pixels_are_red(&png_big, 640, 480);
}

#[test]
fn subrip_and_ass_ssa_conversion_produce_clean_webvtt() {
    let srt_content = b"1\r\n00:00:01,000 --> 00:00:03,500\r\nHello,<br/>world\r\n";
    assert_eq!(
        subtitle_text("captions.srt", srt_content.to_vec()).unwrap(),
        "WEBVTT\n\n1\n00:00:01.000 --> 00:00:03.500\nHello,\nworld\n"
    );

    let ass_content = br#"[Script Info]
Title: Test Episode
ScriptType: v4.00+

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
Dialogue: 0,0:00:01.50,0:00:04.25,Default,,0,0,0,,{\an8}{\i1}Hello, ASS\NSecond line, with comma!{\i0}
Dialogue: 0,0:01:10.05,0:01:12.90,Default,,0,0,0,,{\pos(320,240)}Clean\hspacing
"#;
    let vtt = subtitle_text("episode.ass", ass_content.to_vec()).unwrap();
    assert_eq!(
        vtt,
        "WEBVTT\n\n1\n00:00:01.500 --> 00:00:04.250\nHello, ASS\nSecond line, with comma!\n\n2\n00:01:10.050 --> 00:01:12.900\nClean spacing\n"
    );

    let ssa_content = br#"[Events]
Format: Marked, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
Dialogue: Marked=0,0:00:05.00,0:00:07.00,Default,NTP,0000,0000,0000,!Effect,Classic SSA line
"#;
    let ssa_vtt = subtitle_text("classic.ssa", ssa_content.to_vec()).unwrap();
    assert!(ssa_vtt.starts_with("WEBVTT\n\n1\n00:00:05.000 --> 00:00:07.000\nClassic SSA line\n"));

    assert!(subtitle_text("captions.srt", vec![0xff]).is_err());
    assert!(subtitle_text("captions.vtt", b"<html>not captions</html>".to_vec()).is_err());
    assert!(subtitle_text("captions.ass", b"[Events]\nComment: none".to_vec()).is_err());
    assert!(subtitle_text("captions.vtt", vec![b'a'; MAX_SUBTITLE_BYTES as usize + 1]).is_err());
}

#[test]
fn discovers_subtitle_sidecars_across_same_dir_and_sub_subs_subtitles_folders() {
    let tmp = TestTempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();
    bfs.create_directory_all("movies/sub").unwrap();
    bfs.create_directory_all("movies/Subs/movie_extra").unwrap();
    bfs.create_directory_all("movies/subtitles").unwrap();
    bfs.create_directory_all("shared_captions").unwrap();
    bfs.create_directory_all("docs").unwrap();

    let write_file = |rel: &str, data: &[u8]| {
        let mut up = bfs.begin_upload(rel).unwrap();
        up.write_all(data).unwrap();
        up.commit().unwrap();
    };

    write_file("movies/movie.mp4", b"\0\0\0\x18ftypisom");
    write_file("movies/movie.en.vtt", b"WEBVTT\n\n");
    write_file(
        "movies/sub/movie.fr.srt",
        b"1\n00:00:01,000 --> 00:00:02,000\nBonjour\n",
    );
    write_file(
        "movies/Subs/movie_extra/movie.de.ass",
        b"[Events]\nDialogue: 0,0:00:01.00,0:00:02.00,Default,,0,0,0,,Hallo\n",
    );
    write_file(
        "movies/subtitles/secret.ssa",
        b"[Events]\nDialogue: Marked=0,0:00:01.00,0:00:02.00,Default,,0,0,0,,Secret\n",
    );
    write_file("shared_captions/movie.es.vtt", b"WEBVTT\n\n");
    write_file("shared_captions/forbidden.vtt", b"WEBVTT\n\n");
    write_file("shared_captions/public_sub.vtt", b"WEBVTT\n\n");

    std::os::unix::fs::symlink(
        "../shared_captions/movie.es.vtt",
        tmp.path().join("movies/movie.es.vtt"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "../shared_captions/forbidden.vtt",
        tmp.path().join("movies/movie.ru.vtt"),
    )
    .unwrap();
    // Intermediate hop chain: movies/movie.it.vtt -> ../docs/secret-link -> ../shared_captions/public_sub.vtt
    // Deny intermediate `docs/secret-link` while allowing `movies/movie.it.vtt` and `shared_captions/public_sub.vtt`
    std::os::unix::fs::symlink(
        "../shared_captions/public_sub.vtt",
        tmp.path().join("docs/secret-link"),
    )
    .unwrap();
    std::os::unix::fs::symlink(
        "../docs/secret-link",
        tmp.path().join("movies/movie.it.vtt"),
    )
    .unwrap();

    let discovered = discover_subtitles_in_fs(&bfs, "movies/movie.mp4", |path| {
        !path.ends_with("secret.ssa")
            && !path.ends_with("forbidden.vtt")
            && path != "docs/secret-link"
    })
    .unwrap();

    let paths: Vec<&str> = discovered.iter().map(|t| t.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "movies/movie.en.vtt",
            "movies/movie.es.vtt",
            "movies/Subs/movie_extra/movie.de.ass",
            "movies/sub/movie.fr.srt",
        ]
    );
    assert_eq!(discovered[0].language.as_deref(), Some("en"));
    assert_eq!(discovered[1].language.as_deref(), Some("es"));
    assert_eq!(discovered[3].language.as_deref(), Some("fr"));
}

#[test]
fn epub_parser_extracts_chapters_and_strips_unsafe_scripts_and_svg() {
    let container_xml = br#"<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>"#;

    let content_opf = br#"<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>AetherFlow Architecture Guide</dc:title>
    <dc:creator>Ada Lovelace</dc:creator>
    <dc:language>en</dc:language>
  </metadata>
  <manifest>
    <item id="ch1" href="chapter1.xhtml" media-type="application/xhtml+xml"/>
  </manifest>
  <spine>
    <itemref idref="ch1"/>
  </spine>
</package>"#;

    let chapter1_xhtml = br#"<?xml version="1.0" encoding="utf-8"?>
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <title>Chapter One</title>
    <script>alert('xss-head')</script>
    <style>body { display: none; }</style>
  </head>
  <body>
    <h1>Introduction to Confinement</h1>
    <svg onload="alert('svg-xss')"><script>evil()</script></svg>
    <p onclick="steal()">Descriptor-confined traversal prevents path escapes.</p>
    <iframe src="javascript:alert(1)"></iframe>
    <p>Second safe paragraph &amp; verified output.</p>
  </body>
</html>"#;

    let epub_bytes = build_test_zip(&[
        ("mimetype", b"application/epub+zip", false),
        ("META-INF/container.xml", container_xml, true),
        ("OEBPS/content.opf", content_opf, true),
        ("OEBPS/chapter1.xhtml", chapter1_xhtml, true),
    ]);

    let book = parse_epub_bytes("books/guide.epub", &epub_bytes).unwrap();
    assert_eq!(book.title, "AetherFlow Architecture Guide");
    assert_eq!(book.author.as_deref(), Some("Ada Lovelace"));
    assert_eq!(book.chapters.len(), 1);
    assert_eq!(book.chapters[0].title, "Introduction to Confinement");
    assert!(!book.chapters[0].text.contains("alert"));
    assert!(!book.chapters[0].text.contains("svg"));
    assert!(!book.chapters[0].text.contains("evil"));
    assert!(book.chapters[0]
        .text
        .contains("Descriptor-confined traversal prevents path escapes."));
    assert!(book.chapters[0]
        .text
        .contains("Second safe paragraph & verified output."));
}
