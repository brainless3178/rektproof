//! SVG Badge Generator for Shanon Security Scores
//!
//! Generates embeddable shields.io-style SVG badges showing
//! a protocol's security score and grade.

/// Generate an SVG badge for a protocol's security score.
///
/// The badge follows the shields.io visual style with
/// a left label and right value, color-coded by score.
pub fn generate_badge_svg(score: u8, name: &str) -> String {
    let color = match score {
        90..=100 => "#4c1",
        80..=89 => "#97ca00",
        70..=79 => "#dfb317",
        50..=69 => "#fe7d37",
        _ => "#e05d44",
    };

    let grade = match score {
        95..=100 => "A+",
        90..=94 => "A",
        85..=89 => "A-",
        80..=84 => "B+",
        75..=79 => "B",
        70..=74 => "B-",
        65..=69 => "C+",
        60..=64 => "C",
        50..=59 => "D",
        _ => "F",
    };

    let safe_name = name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .take(20)
        .collect::<String>();

    let label_w: u32 = 120;
    let value_w: u32 = 80;
    let total_w = label_w + value_w;
    let label_cx = label_w / 2;
    let value_cx = label_w + value_w / 2;
    let white = "#fff";
    let shadow = "#010101";
    let bg = "#555";
    let grad_stop = "#bbb";

    let mut svg = String::with_capacity(1200);
    svg.push_str(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20" role="img" aria-label="Shanon: {score}/100">"#
    ));
    svg.push_str(&format!(
        r#"<title>Shanon: {safe_name} {score}/100 ({grade})</title>"#
    ));
    svg.push_str(&format!(
        r#"<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="{grad_stop}" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>"#
    ));
    svg.push_str(&format!(
        r#"<clipPath id="r"><rect width="{total_w}" height="20" rx="3" fill="{white}"/></clipPath>"#
    ));
    svg.push_str(&format!(
        r#"<g clip-path="url(#r)"><rect width="{label_w}" height="20" fill="{bg}"/><rect x="{label_w}" width="{value_w}" height="20" fill="{color}"/><rect width="{total_w}" height="20" fill="url(#s)"/></g>"#
    ));
    svg.push_str(&format!(
        r#"<g fill="{white}" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11">"#
    ));
    svg.push_str(&format!(
        r#"<text x="{label_cx}" y="15" fill="{shadow}" fill-opacity=".3">Shanon Verified</text>"#
    ));
    svg.push_str(&format!(
        r#"<text x="{label_cx}" y="14" fill="{white}">Shanon Verified</text>"#
    ));
    svg.push_str(&format!(
        r#"<text x="{value_cx}" y="15" fill="{shadow}" fill-opacity=".3">{score}/100 {grade}</text>"#
    ));
    svg.push_str(&format!(
        r#"<text x="{value_cx}" y="14" fill="{white}">{score}/100 {grade}</text>"#
    ));
    svg.push_str("</g></svg>");
    svg
}

/// Generate a smaller, compact badge (just score number)
pub fn generate_compact_badge(score: u8) -> String {
    let color = match score {
        90..=100 => "#4c1",
        80..=89 => "#97ca00",
        70..=79 => "#dfb317",
        50..=69 => "#fe7d37",
        _ => "#e05d44",
    };

    let white = "#fff";
    format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="80" height="20" role="img"><rect width="80" height="20" rx="3" fill="{color}"/><text x="40" y="14" fill="{white}" text-anchor="middle" font-family="Verdana,sans-serif" font-size="11">{score}</text></svg>"#,
        color = color,
        white = white,
        score = score,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_badge_contains_score() {
        let svg = generate_badge_svg(85, "Raydium");
        assert!(svg.contains("85/100"));
        assert!(svg.contains("A-"));
        assert!(svg.contains("Raydium"));
    }

    #[test]
    fn test_badge_color_green() {
        let svg = generate_badge_svg(95, "Test");
        assert!(svg.contains("#4c1"));
    }

    #[test]
    fn test_badge_color_red() {
        let svg = generate_badge_svg(30, "Test");
        assert!(svg.contains("#e05d44"));
    }

    #[test]
    fn test_compact_badge() {
        let svg = generate_compact_badge(92);
        assert!(svg.contains("92"));
    }

    #[test]
    fn test_name_sanitization() {
        let svg = generate_badge_svg(80, "Test<script>evil</script>");
        assert!(!svg.contains("<script>"));
    }
}
