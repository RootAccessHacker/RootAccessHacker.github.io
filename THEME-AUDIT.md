# Theme Audit

The theme CSS is intentionally split into exact source CSS plus Hugo compatibility CSS.

## Exact CSS files

`static/css/post.css` is byte-for-byte identical to the uploaded `style.css`.

- uploaded `style.css`: `040f2ae1425e58fb4fbcc166d06ff91c3400a2ec14ca31900d2945b15dedec88`
- theme `static/css/post.css`: `040f2ae1425e58fb4fbcc166d06ff91c3400a2ec14ca31900d2945b15dedec88`

`static/css/home.css` is byte-for-byte identical to the CSS extracted from the uploaded homepage source.

- extracted homepage CSS: `1fa2d8a6eacb889c6aeccc171d22cf5d7e8937da7ba6a3517fd2e988f46ab936`
- theme `static/css/home.css`: `1fa2d8a6eacb889c6aeccc171d22cf5d7e8937da7ba6a3517fd2e988f46ab936`

## Header markup parity

The post header now follows the original article structure:

```html
<header class="header">
    <div>
        <span class="cve-tag">...</span>
        <span class="severity-tag">...</span>
    </div>
    <h1>...</h1>
    <p class="subtitle">... // <span>...</span> // ...</p>
    <div class="meta">
        <div class="meta-item">
            <span class="label">researcher:</span>
            <span class="value">...</span>
        </div>
    </div>
</header>
```

Metadata labels are lowercase and include the colon in the label text, matching the uploaded source. The old generated uppercase labels (`DATE`, `AUTHOR`, `TARGET`, `STATUS`) were removed.

## Hugo compatibility layer

`static/css/hugo-post.css` only adapts Markdown/Chroma output to existing original classes and palette. It does not redefine the original theme variables or original selectors.

## v6 routing note

The contact page is now `content/contact.md` with `url: "/contact/"` and no `date`, so it is always emitted by Hugo without requiring `--buildFuture`.

## v7 note

`static/css/post.css` and `static/css/home.css` remain untouched source copies.
Favicon and Markdown image support are wired through `hugo.toml`, `layouts/_default/baseof.html`, `layouts/_default/_markup/render-image.html`, `layouts/shortcodes/image.html`, and the additive `static/css/hugo-post.css` compatibility layer.

## v10 homepage note

The homepage message/contact card remains in the template and is controlled only by:

```toml
[params.contact]
  enabled = true
```

Set it to `false` to hide the card. The card still uses the original homepage classes: `section`, `contact-section`, `contact-heading`, `contact-text`, `contact-link`, and `contact-note`.

The homepage hero bio is rendered through `.hero-bio` and supports Markdown emphasis, so highlighted words are emitted as `<strong>` and styled by the original `.hero-bio strong` selector from `home.css`.


## v11 note

The Research archive now includes a top back-navigation bar. The styling is isolated in `static/css/research-search.css` and intentionally does not modify `static/css/home.css` or `static/css/post.css`, preserving the original theme CSS.


## Contact page title consistency

`layouts/contact/single.html` renders `/contact/` with the original post navigation/container/content classes while using a `contact-title` compatibility class. This keeps the contact title white like the homepage and research archive titles, without mutating `static/css/post.css`.


## v13 notes

The original theme CSS files remain untouched. The contact title consistency fix is isolated in `static/css/hugo-post.css`, and all return-home labels now render as `← {{ .Site.Params.profile.name }}` from Hugo config rather than hard-coded text.


## v14 math support

Math support was added through a new partial (`layouts/partials/math.html`), two shortcodes (`math`, `mathblock`), and the Markdown fenced-code render hook for `math`, `tex`, and `latex`. The exact copied theme files `static/css/home.css` and `static/css/post.css` were not modified. Math compatibility rules are isolated in `static/css/hugo-post.css`.
