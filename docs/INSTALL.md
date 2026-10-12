# Install and rollback

## Home Assistant OS

Add this Git repository in **Settings → Apps → Install app → ⋮ → Repositories**, then install **H.A.D.E.S. Build Worker**. Older Home Assistant versions may label this menu **Add-ons**.

Keep `enabled: false`. The receiver cannot accept requests until a trusted broker identity is configured. The app is manually started and exposes no host port.

## Build status

This repository contains the complete Home Assistant app build context, but no image build has been performed here. Supervisor image construction, in-OS runtime behavior, and device integration are unverified.

## Rollback

Stop and uninstall this test app from Home Assistant. This does not modify the existing local Build Worker installation. Retain the app data only if the generated test identity and replay ledger are needed; otherwise remove app data through the Home Assistant UI.

## Identity handling

No production private key is shipped. When enabled, the worker creates its own Ed25519 key in app data with mode 0600. The trusted broker public key is configured separately. Never place private keys in the repository or issue reports.