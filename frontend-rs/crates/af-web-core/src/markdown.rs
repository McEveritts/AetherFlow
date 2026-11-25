//! Production Markdown parsing, MathML rendering, and sanitization compile only
//! with `worker-engine` (`af-web-worker`): pulldown-cmark, pulldown-latex, ammonia.
//! The application's `ui` feature uses only the four-line
//! `render_markdown_fallback` HTML escaper (unit tests also compile the engine).

#[cfg(any(feature = "worker-engine", test))]
use pulldown_cmark::{html, Event, Options, Parser};
#[cfg(feature = "ui")]
use qrcode::{render::svg, QrCode};

pub fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
#[cfg(any(feature = "worker-engine", test))]
pub fn render_math(tex: &str, display: bool) -> String {
    let storage = pulldown_latex::Storage::new();
    let parser = pulldown_latex::Parser::new(tex, &storage);
    let mut output = String::new();
    if pulldown_latex::push_mathml(&mut output, parser, pulldown_latex::RenderConfig::default())
        .is_err()
    {
        return format!("<code>{}</code>", escape_html(tex));
    }
    if display {
        output = output.replacen("<math", "<math display=\"block\"", 1);
    }
    output
}
#[cfg(not(any(feature = "worker-engine", test)))]
pub fn render_math(tex: &str, _display: bool) -> String {
    format!("<code>{}</code>", escape_html(tex))
}

#[cfg(any(not(feature = "worker-engine"), test))]
fn render_markdown_fallback(source: &str) -> String {
    format!(
        "<pre class=\"whitespace-pre-wrap\">{}</pre>",
        escape_html(source)
    )
}

#[cfg(not(any(feature = "worker-engine", test)))]
pub fn render_markdown(source: &str) -> String {
    render_markdown_fallback(source)
}

#[cfg(any(feature = "worker-engine", test))]
pub fn render_markdown(source: &str) -> String {
    let options = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_TASKLISTS
        | Options::ENABLE_MATH;
    let events = Parser::new_ext(source, options).map(|event| match event {
        Event::InlineMath(tex) => Event::Html(render_math(&tex, false).into()),
        Event::DisplayMath(tex) => Event::Html(render_math(&tex, true).into()),
        other => other,
    });
    let mut html = String::new();
    html::push_html(&mut html, events);
    ammonia::Builder::default()
        .rm_tags(["img"].iter())
        .add_tags(
            [
                "math",
                "mrow",
                "mi",
                "mn",
                "mo",
                "mtext",
                "mspace",
                "ms",
                "msup",
                "msub",
                "msubsup",
                "mfrac",
                "msqrt",
                "mroot",
                "mover",
                "munder",
                "munderover",
                "mtable",
                "mtr",
                "mtd",
                "mstyle",
                "mpadded",
                "mphantom",
                "menclose",
                "semantics",
                "annotation",
            ]
            .iter(),
        )
        .add_allowed_classes(
            "span",
            [
                "af-token-keyword",
                "af-token-string",
                "af-token-number",
                "af-token-comment",
                "af-token-function",
                "af-token-property",
                "af-token-tag",
            ]
            .iter(),
        )
        .add_allowed_classes("pre", ["whitespace-pre-wrap"].iter())
        .add_tag_attributes("math", ["xmlns", "display"].iter())
        .add_tag_attributes(
            "mo",
            [
                "stretchy",
                "fence",
                "separator",
                "lspace",
                "rspace",
                "minsize",
                "maxsize",
                "largeop",
                "movablelimits",
            ]
            .iter(),
        )
        .add_tag_attributes("mi", ["mathvariant"].iter())
        .add_tag_attributes("mspace", ["width", "height", "depth"].iter())
        .add_tag_attributes(
            "mtd",
            ["columnalign", "rowalign", "columnspan", "rowspan"].iter(),
        )
        .add_tag_attributes(
            "mtable",
            ["columnalign", "rowalign", "columnspacing", "rowspacing"].iter(),
        )
        .clean(&html)
        .to_string()
}
#[cfg(feature = "ui")]
pub async fn render_markdown_async(source: String) -> String {
    match crate::worker_pool::WorkerPool::shared()
        .execute(crate::worker::WorkerRequest::RenderMarkdown {
            source: source.clone(),
        })
        .await
    {
        crate::worker::WorkerResponse::RenderedMarkdown { html } => html,
        _ => render_markdown(&source),
    }
}

#[cfg(feature = "ui")]
pub fn render_qr_svg(payload: &str) -> String {
    match QrCode::new(payload.as_bytes()){
        Ok(code)=>code.render::<svg::Color>().min_dimensions(192,192).quiet_zone(true).build(),
        Err(_)=>"<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 192 192\" role=\"img\" aria-label=\"Payload exceeds QR capacity\"><title>Payload exceeds QR capacity</title></svg>".into(),
    }
}
pub fn highlighted_html(source: &str, spans: &[crate::worker::TokenSpan]) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    for span in spans {
        if span.start < cursor
            || span.end > source.len()
            || !source.is_char_boundary(span.start)
            || !source.is_char_boundary(span.end)
        {
            continue;
        }
        output.push_str(&escape_html(&source[cursor..span.start]));
        let kind = match span.kind.as_str() {
            "keyword" | "string" | "number" | "comment" | "function" | "property" | "tag" => {
                span.kind.as_str()
            }
            _ => "plain",
        };
        output.push_str(&format!(
            "<span class=\"af-token-{kind}\">{}</span>",
            escape_html(&source[span.start..span.end])
        ));
        cursor = span.end;
    }
    output.push_str(&escape_html(&source[cursor..]));
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn markdown_renders_tables_and_real_mathml() {
        let html = render_markdown("# Hello\n\n$x^2 + \\frac{1}{2}$\n\n|a|b|\n|-|-|\n|1|2|");
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("<math"));
        assert!(html.contains("<mfrac>"));
        assert!(html.contains("<table>"));
    }
    #[test]
    fn malicious_markdown_and_math_are_sanitized() {
        let html=render_markdown("<script>alert(1)</script><img src=x onerror=alert(2)>[bad](javascript:alert%281%29)<math><mtext><img onerror='x'></mtext></math>");
        assert!(!html.contains("<script"));
        assert!(!html.contains("onerror"));
        assert!(!html.contains("href=\"javascript:"));
    }
    #[test]
    fn markdown_classes_cannot_impersonate_application_overlays() {
        let rendered = render_markdown(
            "<div class=\"fixed inset-0 z-50 glass-card af-card af-btn af-modal af-popover af-toast\">overlay</div>",
        );
        assert!(rendered.contains("<div>overlay</div>"));
        assert!(!rendered.contains("class="));
        for forbidden in [
            "fixed",
            "glass-card",
            "af-card",
            "af-btn",
            "af-modal",
            "af-popover",
            "af-toast",
        ] {
            assert!(!rendered.contains(forbidden), "{forbidden} in {rendered}");
        }
        let highlighted = render_markdown(
            "<span class=\"af-token-keyword fixed af-modal af-popover af-toast af-card af-btn\">let</span>\n\n<pre class=\"whitespace-pre-wrap fixed af-card\">code</pre>",
        );
        assert!(highlighted.contains("class=\"af-token-keyword\""));
        assert!(highlighted.contains("class=\"whitespace-pre-wrap\""));
        for forbidden in [
            "fixed",
            "af-modal",
            "af-popover",
            "af-toast",
            "af-card",
            "af-btn",
        ] {
            assert!(
                !highlighted.contains(forbidden),
                "{forbidden} in {highlighted}"
            );
        }
    }
    #[test]
    fn markdown_images_cannot_fetch_tracking_beacons() {
        for source in [
            "![beacon](https://evil.example/p.png)",
            "<img src=\"https://evil.example/p.png\">",
            "![same-origin](/api/action)",
            "<img src=\"/api/action\">",
        ] {
            let html = render_markdown(source);
            assert!(!html.contains("<img"), "{html}");
        }
    }
    #[test]
    fn fallback_preserves_text_and_escapes_executable_html() {
        assert_eq!(
            render_markdown_fallback("<script>\"x\" & 'y'</script>\n$café$"),
            "<pre class=\"whitespace-pre-wrap\">&lt;script&gt;&quot;x&quot; &amp; &#39;y&#39;&lt;/script&gt;\n$café$</pre>"
        );
    }
    #[cfg(feature = "ui")]
    #[test]
    fn qr_is_real_vector_and_large_payload_is_handled() {
        let svg = render_qr_svg("https://example.com");
        assert!(svg.contains("<svg"));
        assert!(svg.contains("<path"));
        assert!(!svg.contains("<script"));
        assert!(render_qr_svg(&"x".repeat(10000)).contains("exceeds QR"));
    }
    #[test]
    fn code_highlighting_escapes_source_and_untrusted_classes() {
        let code = "<script>\"x\"</script>";
        let html = highlighted_html(code, &crate::worker::tokenize_code(code, "js"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
