<div align="center">

# 🕸️ RAG Poison Guard — Defend AI Knowledge Bases Against Indirect Prompt Injection

[![Live Sanitizer](https://img.shields.io/badge/🌐_Open_RAG_Poison_Guard-Live_Analyzer-f59e0b?style=for-the-badge)](https://wallisonws.github.io/rag-poison-guard/)
[![Zero Dependencies](https://img.shields.io/badge/Python-Zero_Dependencies-10b981?style=for-the-badge)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-a855f7?style=for-the-badge)](LICENSE)

**Zero-dependency RAG ingestion firewall that strips Invisible Unicode Tag Smuggling (`U+E0000–U+E007F`), BiDi Trojan Source chars, hidden white-text/HTML comment injections, and Markdown image data-exfiltration links before documents reach your Vector DB.**

</div>

```bash
python3 rag_guard.py untrusted_doc.md --out clean_doc.md
```

Created by **[@WallisonWS](https://github.com/WallisonWS)** • MIT License.
