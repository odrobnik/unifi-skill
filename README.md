# UniFi Site Manager API (OpenClaw Skill)

This repository contains the OpenClaw skill definition in **[`SKILL.md`](./SKILL.md)**.

## ClawHub
- Skill page: https://clawhub.ai/skills/unifi-skill
- Install:
  ```bash
  clawhub install unifi-skill --registry "https://auth.clawdhub.com"
  ```

## Local development
- Create a local `config.json` from `config.json.example` (this file is **gitignored**).
- Run scripts from the skill folder, e.g.:
  ```bash
  python3 scripts/unifi.py list-sites
  ```
