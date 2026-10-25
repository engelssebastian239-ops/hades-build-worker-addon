# Security

This repository contains source and non-secret templates only. Never submit private keys, tokens, credentials, or runtime ledgers in issues or pull requests.

The app is restricted to signed read-only diagnostics and starts disabled. The optional GitHub pull path also defaults off and accepts only owner-authored, strictly shaped Ed25519 diagnostic envelopes from the fixed private repository. It provides no shell, model route, package install, or deployment. A GitHub token is provisioned only through authenticated Home Assistant Ingress and stored as a worker-owned mode-0600 file. Do not enable either path until the broker and worker identities have been provisioned separately.

ChatGPT Plus currently has no protected signing-broker integration for the diagnostic request format. Never place the broker private key in ChatGPT, GitHub issues, this repository, or Home Assistant options. See [the pull transport's protocol, key setup, and bootstrap limitations](docs/GITHUB-DIAGNOSTIC-PULL.md).

Use GitHub private vulnerability reporting to notify the repository owner when available.
