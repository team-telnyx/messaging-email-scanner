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

OCR is CPU-intensive (100-500ms per image). To minimize latency impact, OCR is applied selectively:

### When to OCR

1. **Message has spam score > 3.0** — suspicious but not yet rejected
2. **Message has > 80% image content** — images likely contain the spam text

### When to Skip OCR

- Small images (< 10 KiB) — usually logos, signatures, tracking pixels
- Large images (> 10 MiB) — likely photographs, not spam vectors
- More than 3 images — cap to control latency
- Scanner under load — connection/load shedding via `OCR_SKIPPED` symbol

## Configuration

`config/local.d/ocr.conf`:

| Setting | Default | Description |
|---------|---------|-------------|
| `min_size` | 10240 | Minimum image size in bytes |
| `max_size` | 10485760 | Maximum image size in bytes |
| `max_images` | 3 | Max images to OCR per message |
| `timeout` | 10 | Seconds per image |
| `score_threshold` | 3.0 | Min spam score to trigger OCR |
| `image_ratio_threshold` | 0.8 | Min image content ratio |

## Symbols

| Symbol | Score | Description |
|--------|-------|-------------|
| `OCR_PROCESSED` | 0.0 | OCR was applied to this message |
| `OCR_SKIPPED` | 0.0 | OCR was skipped (below threshold or overloaded) |
| `OCR_SPAM_TEXT` | 5.0 | Extracted text matched spam patterns |

## Performance Considerations

- OCR adds 100-500ms per image
- Selective OCR limits impact to suspicious messages only
- Max 3 images per message with 10s timeout each
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
