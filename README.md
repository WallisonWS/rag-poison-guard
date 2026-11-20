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

---

## 🌟 More Free Open-Source Tools by [@WallisonWS](https://github.com/WallisonWS)

If this project saved you time, **leave a ⭐ Star** and explore the rest of the zero-leak, multilingual (EN / PT-BR / ES) suite:

* ⚡ **[headroom-shield](https://github.com/WallisonWS/headroom-shield)** — Zero-Dep LLM Context Compressor (60–95% fewer tokens) + OWASP Shield & MCP Server ([Live Studio](https://wallisonws.github.io/headroom-shield/))
* 🛡️ **[aegis-llm-guard](https://github.com/WallisonWS/aegis-llm-guard)** — Real LGPD/PII Scrub & Rehydration Vault + OWASP LLM Top 10 Firewall ([Live Playground](https://wallisonws.github.io/aegis-llm-guard/))
* 🔬 **[ai-code-sec-scanner](https://github.com/WallisonWS/ai-code-sec-scanner)** — Multi-File SAST Scanner for AI-Generated Code (22 CWE rules + SARIF v2.1) ([Live Scanner](https://wallisonws.github.io/ai-code-sec-scanner/))
* 📈 **[sre-osv-sentinel](https://github.com/WallisonWS/sre-osv-sentinel)** — Google SRE Burn-Rate SLO Engine + Live Google OSV.dev CVE Scanner ([Live Console](https://wallisonws.github.io/sre-osv-sentinel/))
* 🧰 **[devsecops-toolkit](https://github.com/WallisonWS/devsecops-toolkit)** — 18-in-1 Privacy-First DevSecOps, Network, Data & Brazil PIX/CPF Workbench ([Live Studio](https://wallisonws.github.io/devsecops-toolkit/))