# pwnstyle-hugo

A Hugo starter site that ports the uploaded Nimron-style homepage and article theme into reusable Hugo layouts.

## Run locally

```bash
hugo server -D
```

## Create a new post

```bash
hugo new blog/my-new-post/index.md
```

Edit `content/blog/my-new-post/index.md` and set:

```yaml
draft: false
unlisted: false
```

Any non-draft post under `content/blog/` with `unlisted: false` is rendered automatically on the homepage. No manual URL wiring is needed.

## Homepage post card fields

The homepage pulls these fields from each post:

```yaml
title: "My New Post"
cve: "CVE-YYYY-NNNNN"      # optional, displayed in red above the title
severity: "Critical"       # optional fallback tag
tag: "CRITICAL"            # optional explicit tag text
target: "Windows Kernel"   # optional subtitle line
subtitle: "Short summary"  # fallback if target is empty
```

## Identity and links

Repeated identity values live in `hugo.toml`:

```toml
[params.profile]
  name = "Cerberion"
  username = "Cerberion"
  handle = "@Cerberion"
  title = "Security Researcher"

[[params.social_links]]
  key = "x"
  label = "X / Twitter"
  username = "Cerberion"
  handle = "@Cerberion"
  url = "https://x.com/Cerberion"

[[params.social_links]]
  key = "github"
  label = "GitHub"
  username = "RootAccessHacker"
  handle = "RootAccessHacker"
  url = "https://github.com/RootAccessHacker"
```

Changing those values updates the title, hero, contact CTA, post author fallback, and footer/contact links.

The homepage hero bio supports Markdown emphasis, which is how the original homepage gets highlighted words inside `.hero-bio` using the existing `.hero-bio strong` selector:

```toml
[params.profile]
  bio = "**Security research**, **systems internals**, and **low-level engineering** notes."
```

## CSS rule

`static/css/home.css` is the exact extracted homepage CSS from the uploaded homepage source.
`static/css/post.css` is the exact uploaded article `style.css`.
`static/css/hugo-post.css` only maps Hugo/Goldmark/Chroma output onto the existing Nimron classes and palette; it does not redefine the theme variables or original selectors.

## Component gallery

The render test lives at `/blog/component-gallery/`. It is marked `unlisted: true`, so it does not appear on the homepage unless you change that field.


## Creating posts that automatically appear on the homepage

Create a new post:

```bash
hugo new blog/my-new-post/index.md
```

Edit `content/blog/my-new-post/index.md`, then set:

```yaml
draft: false
unlisted: false
```

The homepage lists published pages from `content/blog/` automatically. You do not need to edit the homepage.

The post header uses the original article structure exactly: `cve-tag`, `severity-tag`, `subtitle`, and lowercase metadata labels such as `researcher:`, `target:`, and `reliability:`. If you need fully custom metadata, use this in front matter:

```yaml
meta:
  - label: "researcher:"
    value: "Cerberion (@Cerberion)"
  - label: "target:"
    value: "Windows 11 24H2"
  - label: "reliability:"
    value: "100% deterministic"
```

## Linking a word to your contact / PGP page

A themed contact page is included at `/contact/` in `content/contact.md`.

In any Markdown post, link a specific word like this:

```md
For sensitive reports, use my [PGP key](/contact/).
```

You do not need a special shortcode for normal links. The original CSS already styles `a` tags with the cyan color and hover underline effect. If you want a dedicated page with your PGP key, edit `content/contact.md`; that page uses the same post theme layout and code-block styling.

## Contact / PGP page

The contact page is a normal top-level Hugo page at `content/contact.md` and is pinned to `/contact/` with front matter. It intentionally has no `date` value, so Hugo will not accidentally hide it as future-dated content.

Link to it from any post with standard Markdown:

```md
Use my [PGP key](/contact/) for encrypted mail.
```

Or use the theme shortcode, which reads the URL from `hugo.toml`:

```go-html-template
{{< contactlink text="PGP key" >}}
```

If you are updating an older copy of this theme manually, delete the old `content/contact/index.md` file or folder and use `content/contact.md` instead.


## Favicon / tab icon

Manage tab icons from `hugo.toml`:

```toml
[params.assets]
  favicon_svg = "/favicon.svg"
  favicon = ""
  apple_touch_icon = ""
```

Put the icon files under `static/`. For example, `static/favicon.svg` is served at `/favicon.svg`.
Empty values are ignored.

## Images in posts

Posts are page bundles, so place images next to the post `index.md`:

```text
content/blog/my-new-post/
  index.md
  exploit-flow.png
```

Then use normal Markdown:

```md
![Exploit flow](exploit-flow.png "Exploit flow")
```

The theme has a Markdown image render hook at `layouts/_default/_markup/render-image.html`. It wraps images in the existing Nimron `diagram-phase`, `phase-header`, `diagram-box`, and `memory-caption` classes so images keep the same article styling.

You can also use the explicit shortcode:

```go-html-template
{{< image src="exploit-flow.png" alt="Exploit flow" title="Exploit flow" caption="High-level exploit flow." >}}
```

## SEO, previews, robots, security.txt, and ai.txt

The theme now includes a configurable SEO metadata partial. For each page/post you can set:

```yaml
---
title: "My post title"
description: "A concise search-result summary for this post."
keywords: ["kernel", "windows", "vulnerability research"]
image: "cover.png"
robots: "index,follow"
# noindex: true
---
```

If `image` points to a file in the same page bundle, Hugo uses that file for `og:image` and `twitter:image`.

Global defaults live in `hugo.toml`:

```toml
[params.seo]
  robots = "index,follow"
  twitter_card = "summary_large_image"
  twitter_site = "@Cerberion"
  default_image = ""
  keywords = ["security research", "systems internals", "vulnerability research"]
```

`/robots.txt` is generated from:

```toml
[params.robots]
  allow = ["/"]
  disallow = []
  sitemap = true
```

Static policy files are included here:

```text
static/.well-known/security.txt
static/security.txt
static/ai.txt
```

Before publishing, replace `example.com` and `security@example.com` in those files.


## Research archive and filtering

The footer `Research` link points to `/blog/`. That page now uses `layouts/blog/list.html`, not the generic list template. It only shows each published post's title, CVE/tag/status, and `description`/`subtitle`/`target` text. It does not dump the full Markdown summary into one large clickable entry.

The archive includes a small client-side filter. It searches titles, CVEs, status/severity tags, front matter `tags`, and descriptions.

For best results, give every post a short description:

```yaml
---
draft: false
unlisted: false
description: "A concise one-line description for listings and search previews."
tags: ["kernel", "windows", "exploit-dev"]
---
```

## Optional homepage contact CTA

The homepage message/contact card is controlled from `hugo.toml` and is present by default:

```toml
[params.contact]
  enabled = true
  url = "/contact/"
  action_text = "View contact / PGP"
```

Set `enabled = false` to hide the card completely. The markup is not removed; it is just wrapped in this config switch. By default it points to your internal `/contact/` page, so you are not forced to expose X, GitHub, or any other platform. Footer links remain controlled separately under `[[params.footer_links]]`.


Footer social links are also optional:

```toml
[params.footer]
  show_social_links = false
```

Keep this `false` if you do not want X/GitHub/etc. exposed in the footer. The social-link values can still exist in `hugo.toml` for future use.


## Research archive navigation

The `/blog/` Research archive includes a top `← back to home` bar so visitors can return to `/` without using the browser back button. The archive-specific styling lives in `static/css/research-search.css`; `static/css/home.css` and `static/css/post.css` remain untouched source copies.

### Contact page title consistency

The contact page has its own layout at `layouts/contact/single.html`. It keeps the post-page container, back navigation, section styling, code blocks, and footer, but renders the page title with `contact-title` so it matches the white title convention used on the homepage and `/blog/` research archive. The original `static/css/post.css` remains untouched; the compatibility rule lives in `static/css/hugo-post.css`.


## v13 consistency fixes

All return-home navigation labels now use the configured profile name, for example `← Cerberion`, via `.Site.Params.profile.name`. The contact page has a forced contact layout fallback and an isolated compatibility selector so its page title is white like Home and Research, not neon green like article titles.


## Math notation

Math support is optional so normal pages do not load extra JavaScript. Enable it globally in `hugo.toml`:

```toml
[params.math]
  enabled = true
```

Or enable it only for a single post:

```yaml
---
math: true
---
```

Then write inline math with `\( E = mc^2 \)` or, when `inline_dollar = true`, `$E = mc^2$`. Display math works with `$$...$$`, `\[...\]`, the `mathblock` shortcode, or fenced math blocks:

````md
```math
\Pr[X = k] = {n \choose k} p^k (1-p)^{n-k}
```
````

Shortcodes are also available:

```go-html-template
{{< math >}}\alpha + \beta = \gamma{{< /math >}}
{{< mathblock >}}
\int_{-\infty}^{\infty} e^{-x^2}\,dx = \sqrt{\pi}
{{< /mathblock >}}
```

The original theme CSS files remain untouched; math styling lives in `static/css/hugo-post.css`.
