# Bitlaunch VPS Management CLI

A bash-based command-line interface for managing virtual private servers (VPS) through the Bitlaunch API with cryptocurrency payments, strong privacy, and a fully isolated Docker runtime.

---

## Key Features

- **Privacy & Anonymity**  
  All API calls go through Tor, so your real IP is hidden from providers and intermediaries. API keys and credentials live only inside the container.

- **Ephemeral Identities**  
  The `s. Sign in to another account` option lets you re-authenticate with a new API key after requesting a fresh Tor identity.

- **No Host Footprint**  
  Runs completely inside Docker on macOS/Linux. Nothing is installed on the host OS; on `Ctrl+C` or `x. Exit` all containers and images created by the script are removed.

- **Multi-Provider, Debian-Only VMs**  
  Manage Debian-based VMs on Bitlaunch and DigitalOcean from a single CLI (only Debian images are supported).

- **Crypto-Only Payments**  
  Infrastructure is paid via your Bitlaunch account using BTC, LTC, or ETH.

- **Full VM Lifecycle Management**  
  List, create, restart, rebuild, stop, and remove VMs from a single tool.

- **Simple Text UI**  
  Minimalistic TUI with separate *Main*, *Server*, and *Transactions* menus, suitable for SSH and low-bandwidth environments.
---


## Usage

```bash
bash -c "$(curl -sSfL --http2 --proto '=https'   'https://raw.githubusercontent.com/irenidae/charon/refs/heads/main/bitlaunch.sh')"
```
---

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.
You may copy, distribute and modify the software under the terms of the GPL-3.0.  
See the [`LICENSE`](LICENSE) file for the full text of the license.
