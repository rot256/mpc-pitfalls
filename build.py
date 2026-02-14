import glob
import os
import re
import shutil

import frontmatter
import markdown
from jinja2 import Environment, FileSystemLoader


def slugify(title: str) -> str:
    slug = title.lower()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def protect_math(text: str) -> tuple[str, list[str]]:
    """Replace math expressions with placeholders to prevent markdown mangling."""
    placeholders: list[str] = []

    def _replace(m: re.Match[str]) -> str:
        placeholders.append(m.group(0))
        return f"\x00MATH{len(placeholders) - 1}\x00"

    # Display math first ($$...$$), then inline ($...$)
    text = re.sub(r"\$\$[\s\S]+?\$\$", _replace, text)
    text = re.sub(r"\$[^\n$]+?\$", _replace, text)
    return text, placeholders


def restore_math(html: str, placeholders: list[str]) -> str:
    """Restore math expressions from placeholders."""
    for i, original in enumerate(placeholders):
        html = html.replace(f"\x00MATH{i}\x00", original)
    return html


def build() -> None:
    root = os.path.dirname(os.path.abspath(__file__))
    pitfall_dir = os.path.join(root, "pitfalls")
    dist_dir = os.path.join(root, "dist")

    md = markdown.Markdown(extensions=["extra"])

    pitfalls = []
    for path in sorted(glob.glob(os.path.join(pitfall_dir, "*.md"))):
        post = frontmatter.load(path)
        md.reset()
        protected, placeholders = protect_math(post.content)
        body_html = md.convert(protected)
        body_html = restore_math(body_html, placeholders)
        pitfalls.append(
            {
                "title": post["title"],
                "class": post.get("class", ""),
                "order": post.get("order", 999),
                "slug": slugify(post["title"]),
                "body": body_html,
            }
        )

    pitfalls.sort(key=lambda p: p["order"])

    env = Environment(loader=FileSystemLoader(root), autoescape=False)
    template = env.get_template("template.html")
    html = template.render(pitfalls=pitfalls)

    os.makedirs(dist_dir, exist_ok=True)
    with open(os.path.join(dist_dir, "index.html"), "w") as f:
        f.write(html)

    shutil.copy(os.path.join(root, "style.css"), os.path.join(dist_dir, "style.css"))

    print(f"Built {len(pitfalls)} pitfalls -> dist/index.html")


if __name__ == "__main__":
    build()
