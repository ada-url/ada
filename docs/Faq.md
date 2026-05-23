
# Frequently Asked Questions (FAQ)

## Why are there two separate URL parser implementations?

Ada offers two different URL parser implementations:

- **ada::url**: Optimized for general usage. It stores URL components in separate strings, allowing for fast updates.
- **ada::url_aggregator**: Optimized for performance-critical scenarios. It uses a single string buffer to minimize memory usage, though updates require more processing.

Both implementations share the same API but differ in their internal structures.

---

## Why was the ICU library removed?

The ICU library was used in Ada URL Parser v1.x for Unicode normalization and URL hostname manipulation. However:

- It posed a challenge as ICU might not always be up-to-date on systems.
- Ada introduced its own Unicode functions to ensure broader system support and, in some cases, better performance.

With Ada v2.0, the ICU dependency was completely removed, and the Unicode specification continues to be fully supported.

---

## What performance advantages does Ada URL Parser offer?

Ada is significantly faster than its competitors. According to benchmark results:

- **ada::url_aggregator**: 4.49846M/s (time per URL: 222.298ns)
- **ada::url**: 3.53093M/s
- **Boost**: 2.97994M/s
- **Servo**: 1.45667M/s
- **cURL**: 752.31k/s

Additionally, Node.js with Ada integration is **82% faster than Bun** and 3x faster than Deno.

---

## Which URL components does Ada URL Parser support?

Ada, based on the WHATWG URL specification, supports the following components:

- `protocol_end`: End index of the protocol component.
- `username_end`: End index of the username component.
- `host_start` / `host_end`: Start and end indices of the host component.
- `port`: Port component.
- `pathname_start`: Start index of the pathname.
- `search_start`: Start index of the search parameters.
- `hash_start`: Start index of the hash component.
