use crate::db::TelemetryRecord;
use anyhow::{Context, Result};
use chrono::DateTime;
use image::codecs::png::PngEncoder;
use image::{ImageEncoder, Rgba, RgbaImage};
use serde_json::Value;

pub const CARD_WIDTH: u32 = 500;
pub const CARD_HEIGHT: u32 = 286;

const BG_OBS: Rgba<u8> = Rgba([0x08, 0x0a, 0x18, 255]);
const CARD_FILL: Rgba<u8> = Rgba([0x0f, 0x14, 0x29, 255]);
const TILE_FILL: Rgba<u8> = Rgba([0x14, 0x1a, 0x36, 255]);
const TILE_BORDER: Rgba<u8> = Rgba([0x23, 0x2b, 0x52, 255]);
const DIVIDER: Rgba<u8> = Rgba([0x1e, 0x26, 0x4a, 255]);

const INDIGO_ACCENT: Rgba<u8> = Rgba([0x63, 0x66, 0xf1, 255]);
const INDIGO_LIGHT: Rgba<u8> = Rgba([0x81, 0x8c, 0xf8, 255]);
const FUCHSIA: Rgba<u8> = Rgba([0xd9, 0x46, 0xef, 255]);
const CYAN_DL: Rgba<u8> = Rgba([0x38, 0xbd, 0xf8, 255]);
const EMERALD_PING: Rgba<u8> = Rgba([0x34, 0xd3, 0x99, 255]);
const TEXT_BRIGHT: Rgba<u8> = Rgba([0xe2, 0xe8, 0xf0, 255]);
const TEXT_SLATE: Rgba<u8> = Rgba([0xcb, 0xd5, 0xe1, 255]);
const TEXT_MUTED: Rgba<u8> = Rgba([0x94, 0xa3, 0xb8, 255]);

pub fn render_badge_png(record: &TelemetryRecord, display_id: &str) -> Result<Vec<u8>> {
    let mut img = RgbaImage::from_pixel(CARD_WIDTH, CARD_HEIGHT, BG_OBS);

    // Outer card shell
    fill_rect(&mut img, 10, 10, 480, 266, CARD_FILL);
    stroke_rect(&mut img, 10, 10, 480, 266, TILE_BORDER);

    // Obsidian V2 top gradient strip (#6366f1 -> #d946ef)
    for x in 11..489 {
        let t = (x - 11) as f32 / 478.0;
        let r = lerp_u8(0x63, 0xd9, t);
        let g = lerp_u8(0x66, 0x46, t);
        let b = lerp_u8(0xf1, 0xef, t);
        let c = Rgba([r, g, b, 255]);
        for y in 11..15 {
            img.put_pixel(x, y, c);
        }
    }

    // Header
    fill_circle(&mut img, 30, 34, 5, INDIGO_ACCENT);
    draw_text(&mut img, 44, 27, "SPEEDTEST RESULT", 2, TEXT_BRIGHT);
    draw_text(&mut img, 378, 29, "OBSIDIAN V2", 1, INDIGO_LIGHT);
    draw_hline(&mut img, 24, 476, 50, DIVIDER);

    // Metric grid (2x2)
    // Download tile
    fill_rect(&mut img, 24, 62, 220, 72, TILE_FILL);
    stroke_rect(&mut img, 24, 62, 220, 72, TILE_BORDER);
    draw_text(&mut img, 36, 72, "DOWNLOAD", 1, TEXT_MUTED);
    let dl_val = format_speed(&record.dl);
    let dl_end = draw_text_bounded(&mut img, 36, 92, &dl_val, 3, CYAN_DL, 152);
    draw_text(&mut img, dl_end + 6, 102, "Mbps", 1, INDIGO_LIGHT);

    // Upload tile
    fill_rect(&mut img, 256, 62, 220, 72, TILE_FILL);
    stroke_rect(&mut img, 256, 62, 220, 72, TILE_BORDER);
    draw_text(&mut img, 268, 72, "UPLOAD", 1, TEXT_MUTED);
    let ul_val = format_speed(&record.ul);
    let ul_end = draw_text_bounded(&mut img, 268, 92, &ul_val, 3, FUCHSIA, 152);
    draw_text(&mut img, ul_end + 6, 102, "Mbps", 1, INDIGO_LIGHT);

    // Ping tile
    fill_rect(&mut img, 24, 144, 220, 58, TILE_FILL);
    stroke_rect(&mut img, 24, 144, 220, 58, TILE_BORDER);
    draw_text(&mut img, 36, 154, "PING", 1, TEXT_MUTED);
    let ping_val = format_latency(&record.ping);
    let ping_end = draw_text_bounded(&mut img, 36, 170, &ping_val, 2, EMERALD_PING, 150);
    draw_text(&mut img, ping_end + 6, 174, "ms", 1, TEXT_MUTED);

    // Jitter tile
    fill_rect(&mut img, 256, 144, 220, 58, TILE_FILL);
    stroke_rect(&mut img, 256, 144, 220, 58, TILE_BORDER);
    draw_text(&mut img, 268, 154, "JITTER", 1, TEXT_MUTED);
    let jitter_val = format_latency(&record.jitter);
    let jitter_end = draw_text_bounded(&mut img, 268, 170, &jitter_val, 2, TEXT_SLATE, 150);
    draw_text(&mut img, jitter_end + 6, 174, "ms", 1, TEXT_MUTED);

    // Metadata footer
    draw_hline(&mut img, 24, 476, 214, DIVIDER);

    let isp = extract_isp_display(&record.ispinfo);
    let ts_fmt = format_timestamp_badge(&record.timestamp);

    draw_text(&mut img, 26, 224, "ISP:", 1, TEXT_MUTED);
    draw_text_bounded(&mut img, 64, 224, &isp, 1, TEXT_SLATE, 404);

    draw_text(&mut img, 26, 240, "TIME:", 1, TEXT_MUTED);
    draw_text_bounded(&mut img, 64, 240, &ts_fmt, 1, TEXT_SLATE, 210);

    draw_text(&mut img, 26, 256, "ID:", 1, TEXT_MUTED);
    draw_text_bounded(&mut img, 64, 256, display_id, 1, INDIGO_LIGHT, 210);

    // Bottom-right watermark
    draw_text(
        &mut img,
        326,
        256,
        "LibreSpeed \u{00b7} Obsidian V2",
        1,
        TEXT_MUTED,
    );

    let mut out = Vec::with_capacity(8192);
    PngEncoder::new(&mut out)
        .write_image(
            img.as_raw(),
            CARD_WIDTH,
            CARD_HEIGHT,
            image::ExtendedColorType::Rgba8,
        )
        .context("failed to encode PNG result badge")?;
    Ok(out)
}

pub fn format_speed(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "0.00".to_string();
    }
    match trimmed.parse::<f64>() {
        Ok(v) if v.is_finite() && v >= 0.0 => format!("{v:.2}"),
        _ => "0.00".to_string(),
    }
}

pub fn format_latency(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "0.00".to_string();
    }
    match trimmed.parse::<f64>() {
        Ok(v) if v.is_finite() && v >= 0.0 => {
            if v < 10.0 {
                format!("{v:.2}")
            } else if v < 100.0 {
                format!("{v:.1}")
            } else {
                format!("{:.0}", v.round())
            }
        }
        _ => "0.00".to_string(),
    }
}

pub fn format_timestamp_badge(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return dt.naive_utc().format("%Y-%m-%d %H:%M:%S UTC").to_string();
    }
    if trimmed.chars().count() >= 19 {
        return trimmed
            .chars()
            .take(19)
            .collect::<String>()
            .replace('T', " ");
    }
    if trimmed.is_empty() {
        "Unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn extract_isp_display(ispinfo: &str) -> String {
    let trimmed = ispinfo.trim();
    if trimmed.is_empty() {
        return "Direct / Unknown".to_string();
    }
    let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
        return trimmed.chars().take(48).collect();
    };

    if let Some(raw_isp) = val.get("rawIspInfo") {
        if let Some(obj) = raw_isp.as_object() {
            if let Some(s) = pick_org_from_obj(obj) {
                return s;
            }
        } else if let Some(raw_str) = raw_isp.as_str() {
            let s_trimmed = raw_str.trim();
            if !s_trimmed.is_empty() {
                if let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(s_trimmed) {
                    if let Some(s) = pick_org_from_obj(&obj) {
                        return s;
                    }
                }
            }
        }
    }

    if let Some(processed) = val.get("processedString").and_then(Value::as_str) {
        let clean = processed.trim();
        if let Some((_, rest)) = clean.split_once(" - ") {
            let rest = rest.trim();
            if !rest.is_empty() {
                return rest.to_string();
            }
        }
        if !clean.is_empty() && clean != "0.0.0.0" && clean != "::" {
            return clean.to_string();
        }
    }

    "Direct / Unknown".to_string()
}

fn pick_org_from_obj(obj: &serde_json::Map<String, Value>) -> Option<String> {
    for key in ["org", "isp", "as"] {
        if let Some(v) = obj.get(key).and_then(Value::as_str) {
            let t = v.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    None
}

fn lerp_u8(a: u8, b: u8, t: f32) -> u8 {
    let f = f32::from(a) + (f32::from(b) - f32::from(a)) * t.clamp(0.0, 1.0);
    f.round().clamp(0.0, 255.0) as u8
}

fn fill_rect(img: &mut RgbaImage, x0: u32, y0: u32, w: u32, h: u32, color: Rgba<u8>) {
    let x1 = (x0 + w).min(img.width());
    let y1 = (y0 + h).min(img.height());
    for y in y0..y1 {
        for x in x0..x1 {
            img.put_pixel(x, y, color);
        }
    }
}

fn stroke_rect(img: &mut RgbaImage, x0: u32, y0: u32, w: u32, h: u32, color: Rgba<u8>) {
    if w == 0 || h == 0 {
        return;
    }
    let x1 = (x0 + w - 1).min(img.width() - 1);
    let y1 = (y0 + h - 1).min(img.height() - 1);
    for x in x0..=x1 {
        img.put_pixel(x, y0, color);
        img.put_pixel(x, y1, color);
    }
    for y in y0..=y1 {
        img.put_pixel(x0, y, color);
        img.put_pixel(x1, y, color);
    }
}

fn draw_hline(img: &mut RgbaImage, x0: u32, x1: u32, y: u32, color: Rgba<u8>) {
    if y >= img.height() {
        return;
    }
    let max_x = x1.min(img.width() - 1);
    for x in x0..=max_x {
        img.put_pixel(x, y, color);
    }
}

fn fill_circle(img: &mut RgbaImage, cx: i32, cy: i32, r: i32, color: Rgba<u8>) {
    let r2 = r * r;
    for dy in -r..=r {
        for dx in -r..=r {
            if dx * dx + dy * dy <= r2 {
                let px = cx + dx;
                let py = cy + dy;
                if px >= 0 && py >= 0 && (px as u32) < img.width() && (py as u32) < img.height() {
                    img.put_pixel(px as u32, py as u32, color);
                }
            }
        }
    }
}

fn draw_text(img: &mut RgbaImage, x: u32, y: u32, text: &str, scale: u32, color: Rgba<u8>) -> u32 {
    draw_text_bounded(img, x, y, text, scale, color, img.width().saturating_sub(x))
}

fn draw_text_bounded(
    img: &mut RgbaImage,
    x: u32,
    y: u32,
    text: &str,
    scale: u32,
    color: Rgba<u8>,
    max_width: u32,
) -> u32 {
    let adv = 6 * scale;
    let mut cursor_x = x;
    let limit = x.saturating_add(max_width);

    for ch in text.chars() {
        if cursor_x + 5 * scale > limit {
            break;
        }
        draw_glyph(img, cursor_x, y, ch, scale, color);
        cursor_x += adv;
    }
    cursor_x
}

fn draw_glyph(img: &mut RgbaImage, x: u32, y: u32, ch: char, scale: u32, color: Rgba<u8>) {
    let rows = glyph_5x7(ch);
    for (row_idx, bits) in rows.iter().enumerate() {
        for col_idx in 0..5u32 {
            if (bits >> (4 - col_idx)) & 1 == 1 {
                let px0 = x + col_idx * scale;
                let py0 = y + (row_idx as u32) * scale;
                fill_rect(img, px0, py0, scale, scale, color);
            }
        }
    }
}

/// Compact 5x7 bitmap glyph table covering printable ASCII and middle dot (`·`).
fn glyph_5x7(ch: char) -> [u8; 7] {
    match ch {
        ' ' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        '!' => [0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04],
        '"' => [0x0A, 0x0A, 0x0A, 0x00, 0x00, 0x00, 0x00],
        '#' => [0x0A, 0x1F, 0x0A, 0x0A, 0x1F, 0x0A, 0x00],
        '%' => [0x18, 0x19, 0x02, 0x04, 0x08, 0x13, 0x03],
        '&' => [0x0C, 0x12, 0x14, 0x08, 0x15, 0x12, 0x0D],
        '\'' => [0x04, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00],
        '(' => [0x02, 0x04, 0x08, 0x08, 0x08, 0x04, 0x02],
        ')' => [0x08, 0x04, 0x02, 0x02, 0x02, 0x04, 0x08],
        '*' => [0x00, 0x0A, 0x04, 0x1F, 0x04, 0x0A, 0x00],
        '+' => [0x00, 0x04, 0x04, 0x1F, 0x04, 0x04, 0x00],
        ',' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08],
        '-' => [0x00, 0x00, 0x00, 0x1F, 0x00, 0x00, 0x00],
        '.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x06],
        '/' => [0x01, 0x01, 0x02, 0x04, 0x08, 0x10, 0x10],
        '\u{00b7}' => [0x00, 0x00, 0x04, 0x0E, 0x04, 0x00, 0x00],
        '0' => [0x0E, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0E],
        '1' => [0x04, 0x0C, 0x04, 0x04, 0x04, 0x04, 0x0E],
        '2' => [0x0E, 0x11, 0x01, 0x06, 0x08, 0x10, 0x1F],
        '3' => [0x1F, 0x02, 0x04, 0x06, 0x01, 0x11, 0x0E],
        '4' => [0x02, 0x06, 0x0A, 0x12, 0x1F, 0x02, 0x02],
        '5' => [0x1F, 0x10, 0x1E, 0x01, 0x01, 0x11, 0x0E],
        '6' => [0x06, 0x08, 0x10, 0x1E, 0x11, 0x11, 0x0E],
        '7' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        '8' => [0x0E, 0x11, 0x11, 0x0E, 0x11, 0x11, 0x0E],
        '9' => [0x0E, 0x11, 0x11, 0x0F, 0x01, 0x02, 0x0C],
        ':' => [0x00, 0x06, 0x06, 0x00, 0x06, 0x06, 0x00],
        ';' => [0x00, 0x06, 0x06, 0x00, 0x06, 0x04, 0x08],
        '=' => [0x00, 0x00, 0x1F, 0x00, 0x1F, 0x00, 0x00],
        '?' => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
        '@' => [0x0E, 0x11, 0x17, 0x15, 0x17, 0x10, 0x0E],
        'A' => [0x0E, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'B' => [0x1E, 0x11, 0x11, 0x1E, 0x11, 0x11, 0x1E],
        'C' => [0x0E, 0x11, 0x10, 0x10, 0x10, 0x11, 0x0E],
        'D' => [0x1C, 0x12, 0x11, 0x11, 0x11, 0x12, 0x1C],
        'E' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x1F],
        'F' => [0x1F, 0x10, 0x10, 0x1E, 0x10, 0x10, 0x10],
        'G' => [0x0E, 0x11, 0x10, 0x17, 0x11, 0x11, 0x0F],
        'H' => [0x11, 0x11, 0x11, 0x1F, 0x11, 0x11, 0x11],
        'I' => [0x0E, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
        'J' => [0x07, 0x02, 0x02, 0x02, 0x02, 0x12, 0x0C],
        'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1F],
        'M' => [0x11, 0x1B, 0x15, 0x15, 0x11, 0x11, 0x11],
        'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        'O' => [0x0E, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'P' => [0x1E, 0x11, 0x11, 0x1E, 0x10, 0x10, 0x10],
        'Q' => [0x0E, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0D],
        'R' => [0x1E, 0x11, 0x11, 0x1E, 0x14, 0x12, 0x11],
        'S' => [0x0E, 0x11, 0x10, 0x0E, 0x01, 0x11, 0x0E],
        'T' => [0x1F, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0E],
        'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0A, 0x04],
        'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x1B, 0x11],
        'X' => [0x11, 0x11, 0x0A, 0x04, 0x0A, 0x11, 0x11],
        'Y' => [0x11, 0x11, 0x0A, 0x04, 0x04, 0x04, 0x04],
        'Z' => [0x1F, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1F],
        '[' => [0x0E, 0x08, 0x08, 0x08, 0x08, 0x08, 0x0E],
        ']' => [0x0E, 0x02, 0x02, 0x02, 0x02, 0x02, 0x0E],
        '_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F],
        'a' => [0x00, 0x00, 0x0E, 0x01, 0x0F, 0x11, 0x0F],
        'b' => [0x10, 0x10, 0x16, 0x19, 0x11, 0x11, 0x1E],
        'c' => [0x00, 0x00, 0x0E, 0x10, 0x10, 0x11, 0x0E],
        'd' => [0x01, 0x01, 0x0D, 0x13, 0x11, 0x11, 0x0F],
        'e' => [0x00, 0x00, 0x0E, 0x11, 0x1F, 0x10, 0x0E],
        'f' => [0x06, 0x09, 0x08, 0x1C, 0x08, 0x08, 0x08],
        'g' => [0x00, 0x00, 0x0F, 0x11, 0x0F, 0x01, 0x0E],
        'h' => [0x10, 0x10, 0x16, 0x19, 0x11, 0x11, 0x11],
        'i' => [0x04, 0x00, 0x0C, 0x04, 0x04, 0x04, 0x0E],
        'j' => [0x02, 0x00, 0x06, 0x02, 0x02, 0x12, 0x0C],
        'k' => [0x10, 0x10, 0x12, 0x14, 0x18, 0x14, 0x12],
        'l' => [0x0C, 0x04, 0x04, 0x04, 0x04, 0x04, 0x0E],
        'm' => [0x00, 0x00, 0x1A, 0x15, 0x15, 0x11, 0x11],
        'n' => [0x00, 0x00, 0x16, 0x19, 0x11, 0x11, 0x11],
        'o' => [0x00, 0x00, 0x0E, 0x11, 0x11, 0x11, 0x0E],
        'p' => [0x00, 0x00, 0x1E, 0x11, 0x1E, 0x10, 0x10],
        'q' => [0x00, 0x00, 0x0F, 0x11, 0x0F, 0x01, 0x01],
        'r' => [0x00, 0x00, 0x16, 0x19, 0x10, 0x10, 0x10],
        's' => [0x00, 0x00, 0x0E, 0x10, 0x0E, 0x01, 0x1E],
        't' => [0x08, 0x08, 0x1C, 0x08, 0x08, 0x09, 0x06],
        'u' => [0x00, 0x00, 0x11, 0x11, 0x11, 0x13, 0x0D],
        'v' => [0x00, 0x00, 0x11, 0x11, 0x11, 0x0A, 0x04],
        'w' => [0x00, 0x00, 0x11, 0x11, 0x15, 0x15, 0x0A],
        'x' => [0x00, 0x00, 0x11, 0x0A, 0x04, 0x0A, 0x11],
        'y' => [0x00, 0x00, 0x11, 0x11, 0x0F, 0x01, 0x0E],
        'z' => [0x00, 0x00, 0x1F, 0x02, 0x04, 0x08, 0x1F],
        _ => [0x0E, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_exact_500x286_png_and_formats_latency() {
        assert_eq!(format_latency("3.456"), "3.46");
        assert_eq!(format_latency("18.49"), "18.5");
        assert_eq!(format_latency("142.6"), "143");

        let rec = TelemetryRecord {
            id: 1,
            uuid: "01JABCDEFGHJKMNPQRSTVWXYZ0".to_string(),
            timestamp: "2026-11-15T01:02:03.004Z".to_string(),
            ip: "0.0.0.0".to_string(),
            ispinfo: r#"{"rawIspInfo":"{\"org\":\"AS64500 FiberCo\"}"}"#.to_string(),
            extra: String::new(),
            ua: "curl".to_string(),
            lang: "en".to_string(),
            dl: "940.12".to_string(),
            ul: "880.45".to_string(),
            ping: "2.34".to_string(),
            jitter: "0.42".to_string(),
            log: String::new(),
        };

        let png = render_badge_png(&rec, "01JABCDEFGHJKMNPQRSTVWXYZ0").expect("render png");
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");

        let decoded = image::load_from_memory(&png).expect("decode generated png");
        assert_eq!(decoded.width(), 500);
        assert_eq!(decoded.height(), 286);

        let multibyte_ts = "2026年11月15日T12:34:56extra";
        let badge_ts = format_timestamp_badge(multibyte_ts);
        assert_eq!(badge_ts, "2026年11月15日 12:34:5");
    }
}
