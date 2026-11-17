# Deploying vlpds with Ansible

An example deployment kit: one or more vlpds nodes on plain Ubuntu VPSes, each
running vlpds, Caddy (TLS, handle certificates) and Grafana Alloy (metrics and
logs) under Docker Compose, with Tailscale as the private network for the
operator console, metrics and the cluster's peer port.
[docs/operations/deploy.md](../../docs/operations/deploy.md) explains the
choices; this file is the checklist.

| Path | What |
|---|---|
| `playbooks/bootstrap.yml` | First run on a fresh VPS with only the provider's password login: creates the operator account, then hardens SSH, the firewall, fail2ban and unattended upgrades. |
| `playbooks/vlpds.yml` | Every later run: roles `common`, `vlpds`, `caddy`, `alloy`, one node at a time. |
| `roles/vlpds` | The node itself: config checks, host prep, secrets as files, compose, verify. Its [README](roles/vlpds/README.md) and `defaults/main.yml` document every variable. |
| `roles/common`, `roles/caddy`, `roles/alloy` | Base hardening and Docker, the TLS proxy, metrics and logs. |
| `inventories/example` | A single node serving `pds.example.com`. Copy it. |

## Steps

1. **Tools**: Ansible (ansible-core 2.21 or newer), [sops](https://github.com/getsops/sops)
   with an [age](https://github.com/FiloSottile/age) key, and `sshpass` for the
   bootstrap's one password login. Then, from this directory:

       ansible-galaxy collection install -r requirements.yml

2. **Inventory**: `cp -r inventories/example inventories/<name>` and edit
   `hosts.yml` (address), `group_vars/vlpds.yml` (hostname, bucket, image) and
   `group_vars/all/main.yml` (your SSH key, monitoring endpoint).
3. **Secrets**: `cp .sops.yaml.example .sops.yaml` with your age recipient,
   then `cp inventories/<name>/group_vars/vlpds.sops.yaml.example
   inventories/<name>/group_vars/vlpds.sops.yaml`, fill it in and
   `sops encrypt -i` it. Back up the KEK and the PLC rotation key offline:
   they are not in the bucket.
4. **Bootstrap** (once per fresh host; the provider's password in
   `.bootstrap-pw`, which is gitignored):

       ansible-playbook -i inventories/<name>/hosts.yml playbooks/bootstrap.yml --limit <node>

5. **DNS**: `A` records for the hostname and `*.<handle domain>`.
6. **Deploy**, the first time with the bucket probe:

       ansible-playbook -i inventories/<name>/hosts.yml playbooks/vlpds.yml --check --diff
       ansible-playbook -i inventories/<name>/hosts.yml playbooks/vlpds.yml -e vlpds_preflight_probe=true

7. **First account**: `docker exec vlpds vlpds admin create-invite-code` on the
   node, sign up or [migrate](../../docs/migration.md) an account, then set
   `vlpds_crawlers: ["bsky.network"]` and run the playbook again.

Upgrades: set `vlpds_image` to the new pinned tag and run the playbook (with
`--tags vlpds-deploy,vlpds-verify` for only the node). More nodes:
[Scaling and clustering](../../docs/operations/scaling-and-clustering.md).

## Manual GitHub Actions deploy / rollback

The repo's **Deploy vlpds** workflow (`.github/workflows/deploy.yml`) can apply
a pinned GHCR image to an existing, bootstrapped inventory. It does not create
the server, bucket, DNS, or secrets. Before its first run:

1. Copy and configure `inventories/example/` as `inventories/<name>/` and commit
   its non-secret files and **sops-encrypted** `group_vars/vlpds.sops.yaml`.
   Do not commit a plaintext secrets file. Verify the server SSH host-key
   fingerprint out of band and commit its entry in `deploy/ansible/known_hosts`.
   The runner must have SSH network access to the server; a private-only
   tailnet host needs a self-hosted runner or a separately configured VPN.
2. In GitHub, create an environment named `production` (recommended: require
   reviewers and restrict deployment branches to `main`). Add environment
   secrets `VLPDS_DEPLOY_SSH_KEY` (the operator user's private SSH key) and
   `VLPDS_SOPS_AGE_KEY` (the age identity that decrypts the inventory).
   The operator needs passwordless sudo as configured by bootstrap. Treat these
   secrets as production credentials and rotate them if exposed.
3. In **Actions → Deploy vlpds → Run workflow**, select `main`, choose `deploy`,
   enter the inventory directory name and a full pinned image such as
   `ghcr.io/brittanyellich/vlpds:sha-abcdef0` (after its Image workflow has
   published it). A digest `ghcr.io/brittanyellich/vlpds@sha256:...` works too.
   Do not use `main` or `latest`. Review the run's Ansible verification result.

For **rollback**, run the same workflow with `operation: rollback` and enter
the **previous known-good image reference** in `image`. Record that reference
before every deploy (the workflow's run summary records each successful one).
Rollback redeploys the earlier binary using the *current* inventory and
secrets; it does **not** rewind data, configuration, schema changes or account
state. Check [Upgrades](../../docs/operations/upgrades.md) for compatibility
before rolling back across a feature-level or data migration. A failed health
check does not trigger an automatic rollback: investigate, then explicitly run
the rollback with the known-good image.
