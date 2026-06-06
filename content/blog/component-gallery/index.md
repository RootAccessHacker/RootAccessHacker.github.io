---
title: "Component Gallery"
slug: "component-gallery"
date: 2026-06-05
cve: "STYLE-GUIDE"
severity: "Reference"
target: "Hugo components"
status: "Living reference"
advisory: "Theme Component Gallery"
subtitle: "A render test for the article blocks, code highlighting, tables, timelines, and diagram/chart components."
tldr: "Use this page as a visual regression page. If it renders correctly, the major Nimron-style article components are wired correctly in Hugo."
draft: false
unlisted: true
math: true
---

{{% section title="How to Use This Page" %}}
This page intentionally renders the reusable article components in one place. Keep it around while editing the theme; remove it before publishing if you do not want a public style guide.

Inline code like `NtQuerySystemInformation`, `EPROCESS`, and `Token` now inherits the original cyber-terminal inline style automatically.

Manual token spans also work when you need exact Nimron-style emphasis: <span class="kw">keyword</span>, <span class="fn">function_name</span>, <span class="str">"string"</span>, <span class="cm">/* comment */</span>, <span class="num">0x4141</span>, <span class="type">uint64_t</span>, <span class="op">=</span>, <span class="reg">rax</span>, and <span class="addr">0xfffff800`00000000</span>.
{{% /section %}}



{{% section title="Math Notation" %}}
Enable math on a page by adding `math: true` to front matter. Inline notation works with regular delimiters like \(E = mc^2\), or with the shortcode {{< math >}}\alpha + \beta = \gamma{{< /math >}}.

Display math works with `$$...$$`, `\[...\]`, the `mathblock` shortcode, or a fenced `math` block:

```math
\Pr[X = k] = {n \choose k} p^k (1-p)^{n-k}
```

{{< mathblock >}}
\int_{-\infty}^{\infty} e^{-x^2}\,dx = \sqrt{\pi}
{{< /mathblock >}}
{{% /section %}}

{{% section title="Code Highlighting" %}}
The `codeblock` shortcode now calls Hugo/Chroma. Pass `lang`, or let the shortcode infer the language from `filename`.

{{< codeblock lang="c" filename="example.c" >}}
#include <stdint.h>

static uint64_t rotate_left(uint64_t value, unsigned int shift) {
    return (value << shift) | (value >> (64 - shift));
}

int main(void) {
    uint64_t marker = 0x4141414142424242ULL;
    return (int)(rotate_left(marker, 8) & 0xff);
}
{{< /codeblock >}}

{{< codeblock filename="scanner.py" >}}
def find_marker(blob: bytes, marker: bytes) -> int | None:
    offset = blob.find(marker)
    return offset if offset >= 0 else None
{{< /codeblock >}}
{{% /section %}}

{{% section title="Basic Blocks" %}}
{{< warning title="// Warning" >}}
This is a warning/advisory box for impact notes, caveats, and disclosure reminders.
{{< /warning >}}

{{< chain >}}
Input => State change => Observation => Result
{{< /chain >}}

<table class="info-table">
  <tbody>
    <tr><td>Primitive</td><td>Controlled increment</td></tr>
    <tr><td>Target</td><td>Kernel object field</td></tr>
    <tr><td>Result</td><td><span class="highlight">Security boundary crossed</span></td></tr>
  </tbody>
</table>

{{< timeline >}}
2026-06-05 => Component page added
YYYY-MM-DD => Add your own disclosure milestone
YYYY-MM-DD => Publish the writeup
{{< /timeline >}}
{{% /section %}}

{{% section title="Diagram Phases" %}}
{{< phase num="01" title="Memory Region / Before and After" >}}
<div class="memory-region kernel-region">
  <div class="region-label">Kernel region</div>
  <div class="memory-row">
    <span class="mem-addr">0xfffff800`00001234</span>
    <span class="mem-val before">0x00000000</span>
    <span class="mem-arrow">→</span>
    <span class="mem-val after">0x00000001</span>
    <span class="mem-note">single-byte state transition</span>
  </div>
  <div class="memory-caption">Use this for before/after memory diagrams.</div>
  <div class="diagram-call"><span class="call-label">CALL</span> NtQuerySystemInformation<span class="call-note">example callout using original call-label/call-note classes</span></div>
</div>
<div class="diagram-separator"></div>
{{< /phase >}}

{{< phase num="02" title="Pointer Table" >}}
<div class="memory-region kernel-region">
  <div class="region-label">Pointer table</div>
  <div class="ptr-table">
    <div class="ptr-row dim"><span class="ptr-idx">00</span><span class="ptr-val valid">0xffff...</span><span class="ptr-target">valid pointer</span></div>
    <div class="ptr-row corrupted"><span class="ptr-idx">01</span><span class="ptr-val before">0x00000000</span><span class="ptr-arrow-animate">→</span><span class="ptr-val after">0x00010000</span><span class="ptr-target highlight-red">controlled range</span></div>
    <div class="ptr-row dim"><span class="ptr-idx">02</span><span class="ptr-val valid">0xffff...</span><span class="ptr-target">valid pointer</span></div>
  </div>
</div>
{{< /phase >}}

{{< phase num="03" title="Memory Layout Detection" >}}
<div class="memory-layout">
  <div class="memory-side">
    <div class="region-label">Observed bytes</div>
    <div class="memory-grid">
      <div class="mem-cell header-cell">Offset</div><div class="mem-cell header-cell">Value</div>
      <div class="mem-cell data-cell pattern">+00</div><div class="mem-cell data-cell">41 41 41 41</div>
      <div class="mem-cell data-cell pattern">+04</div><div class="mem-cell data-cell found">42 42 42 42</div>
    </div>
  </div>
  <div class="detection-arrow"><div class="arrow-body"></div><div class="arrow-label">pattern<br>matched</div></div>
  <div class="memory-side">
    <div class="region-label">Mapped object</div>
    <div class="memory-grid">
      <div class="mem-cell header-cell">Field</div><div class="mem-cell header-cell">Value</div>
      <div class="mem-cell data-cell">Header</div><div class="mem-cell data-cell found">valid</div>
      <div class="mem-cell data-cell">Pointer</div><div class="mem-cell data-cell">controlled</div>
    </div>
  </div>
</div>
{{< /phase >}}

{{< phase num="04" title="Struct Layout" >}}
<div class="struct-layout">
  <div class="struct-title">FAKE_OBJECT</div>
  <div class="struct-fields">
    <div class="struct-row"><span class="struct-offset">+0x00</span><span class="struct-name">Magic</span><span class="struct-val">0x41414141</span></div>
    <div class="struct-row important"><span class="struct-offset">+0x08</span><span class="struct-name">Callback</span><span class="struct-val"><span class="struct-field-detail highlight-green">controlled pointer</span><span class="struct-field-detail dim">alignment preserved</span></span></div>
    <div class="struct-row"><span class="struct-offset">+0x10</span><span class="struct-name">Flags</span><span class="struct-val dim">reserved</span></div>
  </div>
</div>

{{< flow >}}
kernel|Kernel validates pointer|original object path
user|User-controlled mapping|fake object layout
kernel|Kernel reads fields|trusted parser path
{{< /flow >}}
{{< /phase >}}

{{< phase num="05" title="Encoding / Decode Steps" >}}
<div class="codepage-compare">
  <div class="codepage-box codepage-bad">
    <div class="codepage-header"><span class="codepage-icon">×</span> Lossy path</div>
    <div class="codepage-body">multi-byte value <span class="codepage-vs">→</span> replacement bytes</div>
    <div class="codepage-verdict">bad</div>
  </div>
  <div class="codepage-box codepage-good">
    <div class="codepage-header"><span class="codepage-icon">✓</span> Lossless path</div>
    <div class="codepage-body">UTF-8 bytes <span class="codepage-vs">→</span> stable decode</div>
    <div class="codepage-verdict">good</div>
  </div>
</div>

<div class="decode-demo">
  <div class="decode-title">Decode example</div>
  <div class="decode-steps">
    <div class="decode-row"><span class="decode-label">input</span><span class="decode-val hl-a">e2 82 ac</span></div>
    <div class="decode-row"><span class="decode-label">formula</span><span class="decode-val decode-formula">b0 | b1 | b2</span></div>
    <div class="decode-row result-row"><span class="decode-label">result</span><span class="decode-val highlight-cyan">stable code point</span></div>
  </div>
</div>
{{< /phase >}}

{{< phase num="06" title="Surrogate / Misaligned Read" >}}
<div class="surrogate-problem">
  <div class="surr-title">Problem</div>
  <div class="surr-example">
    <div class="surr-row bad"><span class="surr-label">aligned</span><span class="surr-bytes"><span class="byte-box byte-ok">AA</span><span class="byte-box byte-ok">BB</span><span class="byte-box byte-bad"><span class="surr-lost">CC</span></span><span class="byte-box byte-bad">DD</span></span><span class="surr-result bad">lost</span></div>
  </div>
  <div class="surr-note">Use this shape to show the lossy interpretation.</div>
</div>
<div class="surrogate-solution">
  <div class="surr-title">Solution</div>
  <div class="surr-example">
    <div class="surr-row ok"><span class="surr-label">shifted</span><span class="surr-bytes"><span class="surr-ok">BB CC</span> DD EE</span><span class="surr-result ok">recovered</span></div>
  </div>
</div>
<div class="offset-diagram">
  <div class="offset-header"><span class="off-label">Read offsets</span></div>
  <div class="byte-strip">
    <div class="byte-cell known-cell"><span class="byte-idx">+00</span><span class="byte-val">AA</span><span class="byte-status">known</span></div>
    <div class="byte-cell unknown-cell"><span class="byte-idx">+01</span><span class="byte-val">??</span><span class="byte-status">unknown</span></div>
    <div class="byte-cell recovered-cell"><span class="byte-idx">+02</span><span class="byte-val">CC</span><span class="byte-status">restored</span></div>
  </div>
  <div class="offset-reads">
    <div class="offset-read read-left"><div class="read-info"><span class="read-label">left read</span><span class="read-pair"><span class="known-val">known-cell</span> + <span class="read-bracket">[gap]</span></span></div></div>
    <div class="offset-read read-right"><div class="read-info"><span class="read-label">right read</span><span class="read-pair"><span class="recovered-val">recovered-cell</span> + <span class="restored">restored</span></span></div></div>
  </div>
  <div class="offset-result">combine partial views</div>
</div>
{{< /phase >}}

{{< phase num="07" title="EPROCESS / Linked Nodes" >}}
<div class="eprocess-fields">
  <div class="eprocess-node system-node">
    <div class="eprocess-header">SYSTEM</div>
    <div class="ep-field"><span class="ep-offset">+0x448</span><span class="ep-val ep-token">Token</span></div>
    <div class="ep-field"><span class="ep-offset">+0x448</span><span class="ep-val ep-match">match</span></div>
  </div>
  <div class="eprocess-link">⇄</div>
  <div class="eprocess-node target-node">
    <div class="eprocess-header">TARGET</div>
    <div class="ep-field highlight-field"><span class="ep-offset">+0x448</span><span class="ep-val ep-ptr">Token pointer</span></div>
  </div>
</div>
{{< /phase >}}

{{< phase num="08" title="Token Bitmask / Write Layout" >}}
<div class="token-layout">
  <div class="token-title">Token privileges</div>
  <div class="token-fields">
    <div class="token-row token-target"><span class="token-offset">+0x40</span><span class="token-name">Present</span><span class="token-desc">available privilege bits</span></div>
    <div class="token-row"><span class="token-offset">+0x48</span><span class="token-name">Enabled</span><span class="token-desc">active privilege bits</span></div>
  </div>
</div>
<div class="bitmask-diagram">
  <div class="bitmask-title">Target bit</div>
  <div class="bitmask-row">
    <span class="bit-group"><span class="bit-label">high</span><span class="bits dim">0000</span></span>
    <span class="bit-group target-bits"><span class="bit-label">target</span><span class="bits hot"><span class="bit">0</span><span class="bit">0</span><span class="bit">0</span><span class="bit">1</span></span></span>
    <span class="bit-group"><span class="bit-label">low</span><span class="bits">0010</span></span>
  </div>
  <div class="bit-annotation">increment affects a specific byte lane</div>
</div>
<div class="write-layout">
  <div class="write-slot"><span class="write-addr">addr+0</span><span class="write-what">byte</span><span class="write-effect">+1</span></div>
  <div class="write-slot"><span class="write-addr">addr+1</span><span class="write-what">byte</span><span class="write-effect">unchanged</span></div>
  <div class="write-target-explain">Use this for byte-oriented write diagrams.</div>
</div>
{{< /phase >}}

{{< phase num="09" title="Injection Flow / Shellcode Box" >}}
<div class="injection-flow">
  <div class="inject-step"><span class="inject-num">01</span><div class="inject-info"><div class="inject-call">OpenProcess</div><div class="inject-detail">target handle</div></div></div>
  <div class="inject-connector">↓</div>
  <div class="inject-step"><span class="inject-num">02</span><div class="inject-info"><div class="inject-call">VirtualAllocEx</div><div class="inject-detail">remote memory</div></div></div>
  <div class="inject-connector">↓</div>
  <div class="inject-step inject-final"><span class="inject-num">03</span><div class="inject-info"><div class="inject-call">CreateRemoteThread</div><div class="inject-detail">execute payload</div></div></div>
</div>
<div class="shellcode-box">
  <div class="shellcode-header">Payload bytes</div>
  <div class="shellcode-hex">48 31 C0 48 FF C0 C3 <span class="shellcode-dim">...</span></div>
  <div class="shellcode-note">placeholder bytes only</div>
</div>
{{< /phase >}}

{{< phase num="10" title="Overflow / Wrap-Around" >}}
<div class="overflow-diagram">
  <div class="overflow-title">Byte overflow</div>
  <div class="overflow-track">
    <span class="overflow-stage"><span class="overflow-label">original</span><span class="overflow-val original">0xfe</span></span>
    <span class="overflow-arrow">→</span>
    <span class="overflow-stage"><span class="overflow-label">increment</span><span class="overflow-val hot-arrow">0xff</span></span>
    <span class="overflow-arrow">→</span>
    <span class="overflow-stage overflow-wrap"><span class="overflow-label">wrap</span><span class="overflow-val wrapping">0x00</span></span>
  </div>
</div>
<div class="compare-approaches">
  <div class="approach-box approach-bad"><div class="approach-header">Bad</div><div class="approach-body"><div class="approach-math"><div class="math-row"><span class="math-label">write size</span><span class="math-val bad-val">too wide</span></div></div><div class="approach-problem">blind overwrite</div></div></div>
  <div class="approach-box approach-good"><div class="approach-header">Good</div><div class="approach-body"><div class="approach-math"><div class="math-row"><span class="math-label">write size</span><span class="math-val good-val">byte lane</span></div></div><div class="approach-problem">byte-aware increment</div></div></div>
</div>
{{< /phase >}}

{{< phase num="11" title="LSB / Overlap / Safety / Race Diagrams" >}}
<div class="lsb-layout">
  <div class="lsb-title">Least-significant-byte write plan</div>
  <div class="lsb-writes">
    <div class="lsb-write"><span class="lsb-addr">+0x00</span><span class="lsb-range">unrelated bytes</span><span class="lsb-effect">unchanged</span><span class="lsb-impact dim">outside target</span></div>
    <div class="lsb-write lsb-hot"><span class="lsb-addr">+0x01</span><span class="lsb-range">target byte lane</span><span class="lsb-effect">incremented</span><span class="lsb-impact">observable state change</span></div>
  </div>
</div>

<div class="byte-overlap-diagram">
  <div class="overlap-title">Byte overlap</div>
  <div class="overlap-strip">
    <div class="overlap-byte ob-other"><span class="ob-addr">+00</span><span class="ob-label">other field</span></div>
    <div class="overlap-byte ob-target"><span class="ob-addr">+01</span><span class="ob-label">target byte</span></div>
    <div class="overlap-byte ob-safe"><span class="ob-addr">+02</span><span class="ob-label">safe byte</span></div>
  </div>
  <div class="overlap-brace-labels"><span class="brace-label brace-write">write window</span><span class="brace-label brace-count">counter field</span></div>
</div>

<div class="safety-diagram">
  <div class="safety-regions">
    <div class="safety-region safe-region"><span class="safety-addr">0x0000 - 0x0fff</span><span class="safety-label">safe region</span><span class="safety-result">ignored</span></div>
    <div class="safety-region target-region"><span class="safety-addr">0x1000 - 0x1fff</span><span class="safety-label">target region</span><span class="safety-result">candidate</span></div>
    <div class="safety-region danger-region"><span class="safety-addr">0x2000 - 0x2fff</span><span class="safety-label">danger region</span><span class="safety-result">avoid</span></div>
  </div>
</div>

<div class="race-diagram">
  <div class="race-row dim"><span class="race-call">T0</span><span class="race-detail">state initialized</span></div>
  <div class="race-row highlight-row"><span class="race-call">T1</span><span class="race-detail">window opens <span class="race-unknown">???</span></span></div>
  <div class="race-row"><span class="race-call">T2</span><span class="race-detail">state consumed</span></div>
</div>
{{< /phase >}}

{{< phase num="12" title="Codepage Flow / Read Logic / Timing / Why Grid" >}}
<div class="codepage-compare">
  <div class="codepage-box codepage-bad">
    <div class="codepage-header"><span class="codepage-icon">×</span> Lossy conversion</div>
    <div class="codepage-body">
      <div class="codepage-flow"><div class="cp-step">input bytes</div><div class="cp-arrow">↓</div><div class="cp-step cp-lossy">replacement</div></div>
      <div class="codepage-verdict">bad path</div>
    </div>
  </div>
  <div class="codepage-box codepage-good">
    <div class="codepage-header"><span class="codepage-icon">✓</span> Stable conversion</div>
    <div class="codepage-body">
      <div class="codepage-flow"><div class="cp-step">input bytes</div><div class="cp-arrow">↓</div><div class="cp-step cp-lossless">round trip</div></div>
      <div class="codepage-verdict">good path</div>
    </div>
  </div>
</div>

<div class="read-info">
  <div class="read-label">Recovered read pair</div>
  <div class="read-pair"><span class="known-val">known</span> + <span class="recovered-val">recovered</span></div>
  <div class="read-decode">decode window: <span class="read-logic">combine stable fragments</span></div>
</div>

<div class="timing-box"><span class="timing-label">Timing</span><span class="timing-value">single pass</span><span class="timing-detail">recheck before publish</span></div>

<div class="why-grid">
  <div class="why-row"><span class="why-read">read</span><span class="why-explain">observe state without changing it</span></div>
  <div class="why-row"><span class="why-read">write</span><span class="why-explain">apply minimal state change</span></div>
</div>
{{< /phase >}}

{{% /section %}}
