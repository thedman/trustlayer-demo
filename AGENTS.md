# AGENTS.md - TrustLayer-demo

# Repository Identity

## Quick Reference

Repository: `TrustLayer-demo`

Classification: Public portfolio demo with static GitHub Pages frontend and Cloudflare Worker proxy

Production: `https://thedman.github.io/trustlayer-demo/`

Hosting: GitHub Pages for static site; Cloudflare Workers for `trustlayer_worker.js`

Deployment: GitHub Actions workflows `pages-static.yml` and `deploy-worker.yml`

Purpose: Demonstrate AI governance control concepts through synthetic vendor/control/audit data.

Highest Context Switch Risk: This repo is in active public use and should be treated as stability-sensitive; do not casually change demo behavior or Worker integration.

Read First: `AGENTS.md`, `README.md`, `.github/workflows/pages-static.yml`, `.github/workflows/deploy-worker.yml`, `wrangler.toml`, `index.html`, `tools.js`, and `trustlayer_worker.js`.

## What this repository IS

This is a public portfolio demonstration of runtime AI governance controls.

It includes a static demo frontend and a Cloudflare Worker proxy for live API-backed behavior when configured.

## What this repository is NOT

- Not a production client system.
- Not connected to real vendor, control, client, or employer data.
- Not a complete proprietary governance methodology.
- Not the Govagentic production website.
- Not a safe place to store API secrets.
- Not a repo to modify casually while job applications or public demos depend on it.

## Purpose

TrustLayer demonstrates how governance can be embedded into AI systems through policy enforcement, decision tracing, audit visibility, and runtime control.

Primary audience: portfolio viewers, prospective employers/clients, and AI governance stakeholders.

Current maturity: public portfolio demo; stability-sensitive.

Source of truth: this file for operational boundaries; `README.md` for public description; workflows and `wrangler.toml` for deployment mechanics.

## Production

- Live demo: `https://thedman.github.io/trustlayer-demo/`.
- Static site: GitHub Pages.
- Worker name: `yellow-bar-4f15` per `wrangler.toml`.
- Required secret: `ANTHROPIC_API_KEY` stored as a Cloudflare secret, not in repository files.

## Hosting

- Static hosting: GitHub Pages.
- Worker hosting: Cloudflare Workers.
- Deployment automation: GitHub Actions.
- DNS/CDN/custom domain: no custom domain documented in repository files.

## Deployment

- Static workflow: `.github/workflows/pages-static.yml`.
- Worker workflow: `.github/workflows/deploy-worker.yml`.
- Static trigger: push to `main` affecting `index.html`, `tools.js`, `vendors.json`, or workflow file.
- Worker trigger: push to `main` affecting `trustlayer_worker.js` or `wrangler.toml`.
- Build system: no static build step documented.
- Rollback: revert the relevant commit and allow the workflow to redeploy; no formal rollback runbook documented.
- Verification: inspect GitHub Pages workflow output, Worker deploy workflow output, live demo behavior, and safe synthetic-data posture.

## Architecture

- Frontend: static HTML/JavaScript.
- Worker/API: Cloudflare Worker proxy.
- Data: synthetic demo data in repository files.
- Backend persistence: none documented.
- Key constraint: preserve synthetic/public-demo boundaries and avoid exposing full proprietary control architecture.

## Analytics

No GA4, Search Console, advertising, app telemetry, or crash reporting is documented in repository files.

## Operational Constraints

- Do not commit secrets or credentials.
- Do not replace synthetic data with real client, employer, or personal data.
- Do not publish a complete proprietary assessment/control method.
- Do not alter deployment workflows casually.
- Preserve public demo stability unless explicitly asked to change behavior.

## Common Context Switch Mistakes

- Do not confuse this with the Govagentic production website.
- Do not assume all hosting is GitHub Pages; the Worker deploys to Cloudflare Workers.
- Do not treat the Worker secret as repository-managed.
- Do not use real vendor or control data.
- Do not modify demo UX or logic casually when public links may be in circulation.

## Repository Decision History

Decision: Split the demo into a static GitHub Pages site and a Cloudflare Worker proxy.

Reason: The portfolio demo needs public static hosting while API secrets must stay server-side.

Implication: Frontend changes and Worker changes deploy through different workflows and must be verified separately.

Decision: Keep all demo data synthetic and incomplete.

Reason: The demo should show reasoning and architecture quality without exposing client data or proprietary methodology.

Implication: Do not make the repository look like a real production governance system or data store.

## AI Agent Guidance

First files to read: `AGENTS.md`, `README.md`, workflow files, `wrangler.toml`, `index.html`, `tools.js`, `vendors.json`, and `trustlayer_worker.js`.

Safe operations: update documentation, review synthetic demo behavior, make small static/Worker changes when explicitly requested, and preserve deployment boundaries.

Restricted operations: do not deploy, push, alter secrets, publish real data, change workflows, or materially alter public demo behavior without explicit instruction.

Verification commands: static inspection and local file review are safe. GitHub Pages and Worker deployment verification require explicit approval or existing workflow output from the user.
