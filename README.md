# Charon

A collection of independent bash-based CLIs for working with various hosting providers and registrars
via their APIs, with a focus on privacy, Tor routing, and cryptocurrency payments.

Each script:
- is fully self-contained (does not depend on other files in this repo),
- can be launched directly via `bash -c "$(curl ...)"`,
- is documented in its own section below.


### Scripts

- [bitlaunch.sh](#bitlaunch-vps-management-cli)
- [njalla.sh](#njalla-domains-management-cli)

_(More scripts coming soon.)_


## Bitlaunch VPS Management CLI

A bash-based command-line interface for managing virtual private servers (VPS) through the Bitlaunch API with cryptocurrency payments, strong privacy, and a fully isolated Docker runtime.


## Features

- **Privacy & Anonymity**  
  All API calls go through Tor, so your real IP is hidden from providers and intermediaries. API keys and credentials live only inside the container.

- **Ephemeral Identities**  
  The `s. Sign in to another account` option lets you re-authenticate with a new API key after requesting a fresh Tor identity.

- **No Host Footprint**  
  Runs completely inside Docker on Mac/Linux. Nothing is installed on the host OS; on `Ctrl+C` or `x. Exit` all containers and images created by the script are removed.

- **Multi-Provider, Debian-Only VMs**  
  Manage Debian-based VMs on Bitlaunch and DigitalOcean from a single CLI (only Debian images are supported).

- **Crypto-Only Payments**  
  Infrastructure is paid via your Bitlaunch account using BTC, LTC, or ETH.

- **Full VM Lifecycle Management**  
  List, create, restart, rebuild, stop, and remove VMs from a single tool.

- **Simple Text UI**  
  Minimalistic TUI with separate *Main*, *Server*, and *Transactions* menus, suitable for SSH and low-bandwidth environments.


## Usage

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/charon/refs/heads/main/bitlaunch.sh')"
```

## Njalla Domains Management CLI

A bash-based command-line interface for managing domains via the Njalla API, with all traffic routed through Tor for strong privacy and an isolated Docker runtime.

## Features

- **Privacy & Anonymity**  
  All API requests go through Tor, so your real IP is hidden from Njalla and intermediaries. API tokens and session data live only inside the container.

- **Ephemeral Identities**  
  You can request a fresh Tor circuit (NEWNYM) at any time and continue working with the same or a new Njalla API token, without leaking host information.

- **No Host Footprint**  
  Runs fully inside Docker on macOS/Linux. Nothing is installed on the host OS; on `Ctrl+C` or when exiting the script, all containers, networks and temporary images created by the script are torn down.

- **Crypto Payments Only**  
  Works with Njalla’s crypto payments model. Supported currencies: **BTC**, **LTC**, **XMR**, **ZEC**, **ETH**.

- **Domain Search & Management**  
  Search for available domains via Njalla’s API, view details for existing domains, and inspect their current status and configuration.

- **Registration & Renewal**  
  Purchase new domains and renew existing ones directly from the CLI, without using a browser.

- **DNS Zone Management**  
  List, add and remove DNS records (A, AAAA, CNAME, MX, TXT, etc.) for your domains, fully through the terminal.

- **Simple Text UI**  
  Minimalistic TUI-style prompts, comfortable for SSH sessions and low-bandwidth connections. No extra dependencies besides Docker and bash.


## Usage

```bash
bash -c "$(curl -sSfL --http2 --proto '=https' 'https://raw.githubusercontent.com/irenidae/charon/refs/heads/main/njalla.sh')"
```

## Donate

If this project is useful to you, consider supporting its development:

XMR: `49nS2i9pTLVYbqv5tUaCGCNSeHQLQkB92QbhbArm14CE77EBf4ewBmPhwuPRfZcJ6GW91Exa399uyLMQXCHZ8S4VNWYmjoN`

Donations are optional but highly appreciated.

## License

This project is licensed under the
[GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).
