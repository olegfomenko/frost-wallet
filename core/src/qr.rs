//! QR code generation and recognition.

use qrcode::{Color, EcLevel, QrCode};

/// A QR symbol as a square matrix of modules, row by row; `true` is dark.
pub struct Matrix {
    pub width: usize,
    pub modules: Vec<bool>,
}

pub fn encode(text: &str) -> Result<Matrix, String> {
    // The codes are shown on a screen or printed by the user, never damaged
    // in transit, so the lowest correction level keeps them as coarse (and
    // as easy to scan) as possible.
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::L)
        .map_err(|_| "The data does not fit into a QR code.".to_string())?;
    Ok(Matrix {
        width: code.width(),
        modules: code
            .to_colors()
            .into_iter()
            .map(|c| c == Color::Dark)
            .collect(),
    })
}

/// Finds and decodes every QR code in an RGBA image.
pub fn decode_rgba(rgba: &[u8], width: usize, height: usize) -> Vec<String> {
    if width == 0 || height == 0 || rgba.len() / 4 < width * height {
        return Vec::new();
    }
    let luma: Vec<u8> = rgba
        .as_chunks::<4>()
        .0
        .iter()
        .take(width * height)
        .map(|px| {
            // Integer BT.601 luma; transparent pixels read as white.
            let y = (299 * px[0] as u32 + 587 * px[1] as u32 + 114 * px[2] as u32) / 1000;
            let a = px[3] as u32;
            ((y * a + 255 * (255 - a)) / 255) as u8
        })
        .collect();
    decode_luma(&luma, width, height)
}

pub fn decode_luma(luma: &[u8], width: usize, height: usize) -> Vec<String> {
    let mut image =
        rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| luma[y * width + x]);
    image
        .detect_grids()
        .iter()
        .filter_map(|grid| grid.decode().ok())
        .map(|(_, content)| content)
        .collect()
}
