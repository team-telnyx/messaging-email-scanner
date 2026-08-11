# MSG-1797: Tesseract OCR for Image-Based Spam Detection

## Overview

Spammers embed spam text in images to evade text-based content filters. This module uses Tesseract OCR to extract text from images in email attachments and feeds it to the Bayes classifier and content rules.

## Tesseract Installation

Tesseract OCR is installed in the Rspamd Docker image:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    && rm -rf /var/lib/apt/lists/*
```

## Selective OCR Strategy

OCR is CPU-intensive (typically 100-300ms per image). To minimize latency impact, OCR is applied selectively:

### When to OCR

OCR runs only when a message has **> 80% decoded image content**. Images that
dominate the MIME payload are likely to contain text that ordinary content
rules cannot see.

OCR is a prefilter so its extracted text is available to normal rules and
Bayes. A prefilter cannot see the final Rspamd score, so score-based selection
does not work here. Implementing score-based selection would require a
postfilter; a postfilter runs after scoring and is therefore too late to inject
OCR text into the scan that produced that score.

### When to Skip OCR

- Small images (< 10 KiB) — usually logos, signatures, tracking pixels
- Large images (> 10 MiB) — likely photographs, not spam vectors
- More than 1 eligible image — cap to control latency
- Scanner under load — connection/load shedding via `OCR_SKIPPED` symbol

## Configuration

`config/local.d/ocr.conf`:

| Setting | Default | Description |
|---------|---------|-------------|
| `min_size` | 10240 | Minimum image size in bytes |
| `max_size` | 10485760 | Maximum image size in bytes |
| `max_images` | 1 | Maximum images to OCR per message |
| `timeout` | 2 | Hard process-kill guard in seconds for the image |
| `image_ratio_threshold` | 0.8 | Min image content ratio |

## Symbols

| Symbol | Score | Description |
|--------|-------|-------------|
| `OCR_PROCESSED` | 0.0 | OCR was applied to this message |
| `OCR_SKIPPED` | 0.0 | OCR was skipped (below threshold or overloaded) |
| `OCR_SPAM_TEXT` | 5.0 | Extracted text matched spam patterns |

### Existing `R_EMPTY_IMAGE` signal

`R_EMPTY_IMAGE` is an existing Rspamd 3.10 rule in `rules/html.lua`, scored at
2.0. It detects a nearly empty HTML part (less than 50 bytes of text) containing
a large image whose declared width plus height is at least 400 pixels and which
is not nested in a link. It is complementary to OCR: it identifies the HTML
layout, while the custom plugin extracts text from eligible image MIME parts.

It does not fire for every standalone image attachment and does not perform OCR
itself. `tests/ocr_test.sh` includes a multipart/related fixture with an empty
HTML body and a large CID image, and verifies that `R_EMPTY_IMAGE` and
`OCR_PROCESSED` are both emitted by this setup.

## Performance Considerations

- OCR typically adds 100-300ms for the selected image
- Selective OCR limits impact to messages with >80% decoded image content
- Only one image is attempted per message, with a 2s hard kill guard
- Normal completion must remain inside KumoMTA's 500ms scanner timeout; monitor
  scan latency and treat the process timeout as cleanup protection, not a budget
- Load shedding when scanner is overloaded

## Language Packs

To add additional languages:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr-eng \
    tesseract-ocr-spa \
    tesseract-ocr-fra \
    && rm -rf /var/lib/apt/lists/*
```
