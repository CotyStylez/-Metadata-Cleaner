# ExifZero Enterprise — Client-Side Metadata Sanitization & Forensic Inspection Suite

A professional, corporate-grade digital asset privacy workstation running 100% inside the browser. Enables privacy officers, creative teams, legal departments, and individuals to deeply inspect, audit, and completely strip EXIF, GPS coordinates, device fingerprints, and IPTC/XMP metadata from batches of images before distribution, with zero cloud uploads or telemetry.

---

### User Review & Critical Decisions

> [!IMPORTANT]
> The following product specifications were confirmed during Phase 1 clarification:
> - **Metadata Inspection**: Deep forensic inspection with side-by-side Before vs. After comparison for individual images and batches.
> - **Format Coverage**: Comprehensive support covering JPG, PNG, WebP, TIFF, GIF, HEIC, and AVIF.
> - **Visual Aesthetic**: Dual-theme enterprise suite with high-contrast corporate light and executive dark slate modes.

---

### 1. Overview & Core Concept

- **What It Does**: ExifZero Enterprise is a local browser workstation that allows users to drag and drop batches of images, inspect every embedded metadata tag (GPS, camera model, lens serial, software versions, creation timestamps), scrub all tracking artifacts in client-side memory, and export sanitized images individually or as a structured ZIP archive.
- **Target Audience & Persona**: Corporate compliance officers, legal teams, privacy-conscious photojournalists, photographers, and security engineers who must ensure zero identifiable metadata leaves the device.
- **Key Value**: Guarantees complete data sovereignty. No server uploads, no network dependencies, and no privacy compromises, packaged in an enterprise workflow that matches commercial desktop software.

---

### 2. User Experience & Visual Design

#### Key User Flows
1. **Asset Ingestion**: User drags a batch of photos or folders onto the dropzone or selects via file picker (JPG, PNG, WebP, TIFF, GIF, HEIC, AVIF).
2. **Batch Queue & Health Overview**: Files immediately populate an enterprise queue table showing thumbnails, file names, sizes, detected metadata count, and GPS status.
3. **Deep Forensic Inspection**: Clicking any image opens the Inspector Drawer/Panel displaying:
   - **Original Metadata Audit**: Structured breakdown of GPS coordinates, Camera/Hardware IDs, Lens specs, Author/Copyright tags, and Embedded thumbnails.
   - **Before vs. After Diff**: Side-by-side tag comparison confirming that the sanitized output contains zero metadata bytes.
4. **Custom Batch Renaming & Optimization**: User configures naming schemas (prefix, counter padding, timestamps) and output format/quality settings.
5. **Sanitization & Export**: Real-time client-side processing via Canvas rendering and binary header stripping, followed by one-click ZIP download or individual file export.

#### Visual Identity & Theme
- **Aesthetic Direction**: High-density enterprise SaaS utility; authoritative, precise, and utilitarian with zero decorative fluff.
- **Color Palette & Dual-Theme Tokens**:
  - *Executive Dark*: Background `#0B0F19`, Surface `#111827`, Hairline Border `#1F2937`, Primary Accent `#4F46E5` / `#6366F1`, Text `#F9FAFB` / `#9CA3AF`.
  - *Corporate Light*: Background `#F8FAFC`, Surface `#FFFFFF`, Hairline Border `#E2E8F0`, Primary Accent `#4338CA`, Text `#0F172A` / `#64748B`.
  - *Audit Accents*: Clean Green (`#16A34A` / `#22C55E`) for sanitized zero-state; Muted Amber (`#D97706`) for detected GPS coordinates.
- **Typography & Scale**:
  - Display & Headings: `Plus Jakarta Sans` (font-semibold, tracking-tight).
  - Body & Microcopy: `Plus Jakarta Sans` (400 weight, 14px–15px).
  - Data & Metadata: `JetBrains Mono` / `tabular-nums` for coordinates, tag keys, byte offsets, and hex identifiers.
- **Zero-Pill Discipline & Spatial Balance**:
  - No candy pill enclosures for static metadata tags. All file statuses and metadata tags render as clean unboxed text separated by `·` or `/`.
  - Single-elevation depth with 1px hairline dividers.
  - Interactive tabs (Overview, Metadata Diff, Settings) styled as sleek segmented controls with click handlers.

---

### 3. Key Product Decisions & Trade-Offs

- **Decision 1: In-Memory Pure Browser Processing**
  - *Chosen Approach*: Decoding images into browser Canvas / OffscreenCanvas and reconstructing pure image pixel buffers without original header segments (APP1, EXIF, XMP).
  - *Why*: Provides a 100% mathematical guarantee that no proprietary metadata markers survive in the exported file, while executing at near-instant native speeds.
  - *Alternatives Considered*: Server-side ExifTool proxy (rejected: violates zero-upload privacy contract).

- **Decision 2: Deep Forensic Tag Parser**
  - *Chosen Approach*: Embedded binary EXIF, IPTC, and TIFF parser that extracts raw tags, GPS coordinates, camera maker notes, and software stamps directly from the ArrayBuffer.
  - *Why*: Allows users to clearly audit exactly what private information was lurking in their photo before stripping it.

- **Decision 3: Dual-Theme Architecture with CSS Variables**
  - *Chosen Approach*: Semantic CSS custom properties toggled via `data-theme="dark"` / `data-theme="light"` on `<html>`, persisted in `localStorage`.
  - *Why*: Provides instant flicker-free switching between enterprise light office mode and dark workstation mode.

---

### 4. Technical Architecture & Data Strategy

```
┌────────────────────────────────────────────────────────────────────────┐
│                        ExifZero Enterprise UI                         │
├────────────────────────────────────────────────────────────────────────┤
│  Top Bar: Wordmark (Single Line) ── Navigation ── Theme Toggle ── Export │
├──────────────────────────────────┬─────────────────────────────────────┤
│        Asset Queue & Batch        │       Forensic Inspector Panel      │
│  - Multi-format Drag & Drop Zone │  - Side-by-Side Tag Comparison     │
│  - High-density File Data Table  │  - GPS & Hardware Identification   │
│  - Batch Renaming Rule Engine    │  - Sanitized Zero-Metadata Proof   │
│  - Processing Progress & Actions │  - Single Asset Download Preview   │
└──────────────────────────────────┴─────────────────────────────────────┘
                                   │
               ┌───────────────────┴───────────────────┐
               ▼                                       ▼
    [ Binary EXIF / TIFF Parser ]           [ Canvas / Binary Stripper ]
    - Extracts GPS, Camera, Date,           - Renders clean pixel buffer
      Author, Software, Dimensions          - Strips APP1 / EXIF markers
    - Calculates metadata byte weight       - Re-encodes pure JPG/PNG/WebP
               │                                       │
               └───────────────────┬───────────────────┘
                                   ▼
                         [ Client-Side JSZip ]
                         - Batch archive generator
                         - Direct browser blob download
```

#### Data Model & Entities
- `AssetItem`:
  - `id`: unique UUID
  - `file`: original File object
  - `name`: original filename
  - `size`: raw byte size
  - `type`: MIME type
  - `previewUrl`: Object URL for thumbnail
  - `metadata`: object containing parsed EXIF fields (GPS, Camera, Lens, Date, Software, RawTags)
  - `status`: `'pending' | 'processing' | 'sanitized' | 'error'`
  - `sanitizedBlob`: stripped Blob object
  - `sanitizedSize`: clean output byte size
  - `cleanedName`: computed renamed output filename

#### Interactive Component & State Mapping
- `ThemeController`: Manages light/dark theme preference, persists to localStorage, updates CSS root tokens.
- `BatchManager`: Handles multi-file drop, MIME type validation, queue addition, and bulk operations (Clear All, Sanitize All).
- `InspectorDrawer`: Observes selected asset, displays raw tag key-value pairs, formats GPS latitude/longitude with offline coordinate map viewer, and renders Before vs. After diff.
- `RenamerConfig`: Dynamic template engine applying prefix, auto-increment padding, and output formats.
- `ArchiveEngine`: Assembles sanitized blobs into a ZIP file with real-time compression progress indicator.
