# EndGame V3 — Self-Hosted Anti-DDoS Front for Tor & I2P

EndGame V3 is a front-end shield that sits in front of your origin service (onion or i2p). It filters abusive traffic, rate-limits hostile clients, and challenges bots with a lightweight captcha—so legitimate users can reach your site while attacks are absorbed at the edge.

> **TL;DR**  
> • **Free** to use, **self-hosted**, and runs locally (no third parties).  
> • Works with **Tor** and **I2P**.  
> • Optional **GoBalance** load-balancing for large scale.  
> • Hardened defaults (fail2ban, rkhunter, chkrootkit) and tuned kernel/sysctl.

---

## Table of Contents
- [How It Works](#how-it-works)
- [Key Features](#key-features)
- [Requirements](#requirements)
- [Before You Begin (Trust & Safety)](#before-you-begin-trust--safety)
- [Quick Start](#quick-start)
- [Configuration Guide](#configuration-guide)
- [Branding the Front](#branding-the-front)
- [Going Big: GoBalance](#going-big-gobalance)
- [Tech Stack](#tech-stack)
- [Support](#support)
- [License](#license)
- [Repo: Commit & Push](#repo-commit--push)

---

## How It Works

**Traffic path:**


- Run **EndGame** on a separate machine from your origin.
- EndGame proxies only **clean** requests to your backend.
- With **GoBalance**, many EndGame fronts can sit behind a single “master onion,” distributing load under heavy traffic.

---

## Key Features

- **Powerful request filtering** with NGINX + Lua, including inline captcha.
- **Rate limiting** aware of Tor v3 circuit IDs, plus secondary cookie-based limits.
- **I2P and Tor support** out of the box (toggle per your threat model).
- **Hardening & compromise checks**: fail2ban, rkhunter, chkrootkit, debsecan.
- **Performance tuning**: kernel/sysctl tweaks, module caching.
- **GoBalance** (Go rewrite of onionbalance) for high-traffic scaling.
- **Captcha in Rust** (no runtime deps) for fast challenge pages.
- **Easy theming**: color, logo, favicon for queue/captcha pages.

---

## Requirements

- **Fresh Debian 12 (bookworm)** host with root (or passwordless sudo).
- Network access suitable for Tor and/or I2P (depending on your setup).
- A separate **origin server** (onion or local lan) to receive proxied traffic.

> **Note:** Older docs sometimes mention Debian 11. Use **Debian 12 (bookworm)** for the included installer.

---

## Before You Begin (Trust & Safety)

- **Obtain EndGame from a trusted source**. Do not blindly clone random forks.
- Verify signatures when available.
- Keep your **KEY** and **SALT** (cookie crypto) secret and unique.
- Understand your legal requirements when operating darknet services.

---

## Quick Start

1) **(Optional) Build GoBalance**  
   - Compile GoBalance (Go required) and generate its config.  
   - Note your `MASTERONION` (the master onion that signs/publishes descriptors).

2) **Edit `endgame.config`**  
   - Set a strong `TORAUTHPASSWORD`.  
   - Choose your routing mode:
     - **Tor proxy mode:** set `BACKENDONION1/2` to your origin onion(s) for redundancy.
     - **Local proxy mode:** set `LOCALPROXY=true` and `PROXYPASSURL=http://<origin-ip>:<port>`.
   - Set secure cookie values:
     - `KEY` — 68–128 random alphanumeric characters.
     - `SALT` — exactly 8 alphanumeric characters.

3) **Brand the front** (recommended)  
   - Colors: `HEXCOLOR`, `HEXCOLORDARK`  
   - Identity: `SITENAME`, `SITETAGLINE`, `SITESINCE`  
   - Assets (Base64): `FAVICON`, `SQUARELOGO`, `NETWORKLOGO`

4) **Install on a fresh Debian 12 host**  
   - Transfer the prepared archive (excluding the `sourcecode` if instructed).  
   - As **root**:
     ```bash
     ./setup.sh
     ```
   - The script installs dependencies, configures Tor/I2P (as enabled), hardens the system, creates services, and outputs your onion (and I2P) addresses.

5) **Go live**  
   - Share your new front onion with users **or** add it to GoBalance so a single master onion spreads load across multiple fronts.

---

## Configuration Guide

- **Tor setup toggles:** `TORSETUP=true`, optional `TORINTRODEFENSE=true`, `TORPOWDEFENSE=true`
- **I2P setup toggle:** `I2PSETUP=true`
- **Session & rate limits:** tune session length, request/stream rate in the config.
- **Local vs Tor backend:**
  - Local proxy ⇒ `LOCALPROXY=true`, `PROXYPASSURL=http://<origin>`
  - Tor proxy ⇒ set `BACKENDONION1/2` and leave `LOCALPROXY=false`

> **Tip:** Keep separate configs for staging and production. Rotate `KEY`/`SALT` if you suspect leakage.

---

## Branding the Front

- **Queue page and captcha** can be themed:
  - Primary color: `HEXCOLOR`
  - Darker shade: `HEXCOLORDARK`
  - Logos/Favicon: base64 strings to avoid extra requests on first load
- Branding helps users recognize the official front and reduces confusion.

---

## Going Big: GoBalance

- Use **GoBalance** to publish **descriptors** that point users to many EndGame fronts from a single **master onion**.
- Benefits:
  - Load distribution under DDoS.
  - Fault isolation if a single front is saturated.
- For very large fleets, you can split work across multiple GoBalance + Tor processes.

---

## Tech Stack

- **NGINX** (with naxsi, headers-more, echo, Lua modules)  
- **LuaJIT**, **lua-resty-*** libraries  
- **Tor**, **NYX**, **socat** (as configured)  
- **I2P (i2pd)** (optional)  
- **Security tools**: fail2ban, rkhunter, chkrootkit, debsecan  
- **GoBalance** (Go) and **Rust captcha**

---

## Support

Need help installing or tuning? We provide **free install guidance** (brand setup, config review, operational tips).

- Website: **.com**  
- Open an issue in this repo with details about your environment.

---

## License

Released under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.
You may copy, modify, and redistribute under the terms of AGPL-3.0. If you offer this work as a **network service**, you must provide the complete corresponding source to users of the service.

See [LICENSE](./LICENSE) for the full text.

**Copyright © 2025 eckmar-official contributors.**