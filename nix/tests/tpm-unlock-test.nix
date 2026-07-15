# Copyright 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

{ pkgs, basilTpm }:

# ---------------------------------------------------------------------
# tests.tpm-unlock: hermetic multi-node nixosTest VM lane.
# ---------------------------------------------------------------------
# Ports the Phase-1 shell harness (scripts/tpm-unlock-e2e.sh) into a
# content-addressed nixosTest. `basilTpm` (built with --features
# unlock-tpm) is BAKED INTO the guest images from THIS flake (no virtfs
# share); each TPM guest gets an emulated TPM 2.0 via
# `virtualisation.tpm.enable`. Linux-only (gated below): nixosTest builds
# a NixOS guest, meaningless on darwin.
#
# Topology:
#   tpmnode  : TPM + an in-VM OpenBao dev backend. Scenario A
#              (basil-h8qq.2): seal a TPM-ONLY unlock slot, auto-unlock
#              with NO operator secret, sign+verify over the unix socket,
#              then shutdown()/start() reusing the persisted swtpm state
#              and auto-unlock + sign+verify AGAIN. Plus Scenario B PCR
#              mismatch (perturb a policy PCR -> fail closed).
#   notpm    : NO TPM. Scenario B CASE 1: a TPM-only bundle fails closed;
#              a bundle that ALSO has a passphrase recovery slot opens via
#              passphrase. Bundles are transferred from tpmnode.
#   othertpm : a SECOND, DIFFERENT emulated TPM. Scenario B CASE 3: the
#              tpmnode-sealed blob cannot be unsealed by a foreign TPM
#              (does-not-move-with-a-disk-image) -> fail closed.
#
# A green `nix build .#tests.<sys>.tpm-unlock` == the testScript passed.
pkgs.testers.nixosTest {
  name = "basil-tpm-unlock";

  nodes.tpmnode =
    { pkgs, ... }:
    {
      # NixOS wires swtpm + the qemu -tpmdev/-device automatically; the
      # guest gets an emulated TPM 2.0 as /dev/tpm0 + /dev/tpmrm0, whose
      # state persists across machine.shutdown()/start() within a run.
      virtualisation.tpm.enable = true;
      virtualisation.memorySize = 2048;
      environment.systemPackages = [
        basilTpm
        pkgs.openbao
        pkgs.tpm2-tools
      ];
      # The live backend the broker reaches for sign/verify is an
      # in-memory, auto-unsealed OpenBao dev server. It is NOT a
      # persistent systemd unit: `bao -dev` run as a bare unit fully
      # unseals but then exits and restart-loops to start-limit-hit
      # (no login environment). Instead `provision_backend` in the
      # testScript launches it ad hoc through the test driver's root
      # shell and polls `bao status`, exactly how
      # scripts/prefill-test-store.sh and init_flow_e2e.rs bring up a
      # dev backend. In-memory state is lost on a guest reboot, so the
      # testScript re-provisions transit each boot and the catalog's
      # example key is `missing=generate` (startup reconcile recreates
      # it). The sealed bundle still carries the same dev root token,
      # so the post-reboot auto-unlock reaches the fresh backend.
    };

  nodes.notpm =
    { ... }:
    {
      virtualisation.tpm.enable = false;
      environment.systemPackages = [ basilTpm ];
    };

  nodes.othertpm =
    { pkgs, ... }:
    {
      virtualisation.tpm.enable = true;
      environment.systemPackages = [
        basilTpm
        pkgs.tpm2-tools
      ];
    };

  testScript = ''
    import base64

    basil = "/run/current-system/sw/bin/basil"

    # --- scaffold fixtures (written via base64 so no shell-quoting/heredoc
    # --- or nix-indentation hazards leak into JSON/TOML content). ---------
    CATALOG_A = '{"schema":"catalog","backends":{"primary":{"kind":"vault","addr":"http://127.0.0.1:8200","engines":["transit"],"capabilities":[],"mintKeyTypes":["ed25519"]}},"keys":{"example.signing_key":{"class":"asymmetric","keyType":"ed25519","backend":"primary","engine":"transit","path":"example-signing-key","writable":true,"missing":"generate","description":"TPM-unlock e2e signer"}}}'
    POLICY_A = '{"schema":"policy","subjects":{"breakglass.root":{"breakGlass":true,"allOf":[{"kind":"unix","uid":0}]}},"roles":{"signer":["sign","verify","get_public_key"]},"rules":[{"id":"tpm-e2e-signer","subjects":["breakglass.root"],"action":["role:signer"],"target":["example.signing_key"]}],"config":{"names":{"users":{"0":"root"},"groups":{}},"memberships":{"0":[0]}}}'
    CATALOG_ZERO = '{"schema":"catalog","backends":{"primary":{"kind":"vault","addr":"http://127.0.0.1:8200","engines":["transit"],"capabilities":[]}},"keys":{}}'
    POLICY_ZERO = '{"schema":"policy","roles":{},"rules":[],"config":{"names":{"users":{},"groups":{}},"memberships":{}}}'
    TOML_TPM = 'schema = "agent"\nschemaVersion = 3\nvault-addr = "http://127.0.0.1:8200"\nsocket = "/root/basil.sock"\n[import]\ncatalog = "/root/catalog.json"\npolicy = "/root/policy.json"\nbundle = "/root/b-tpm.sealed"\n[unlock]\nunlock-tpm = true\n'
    TOML_TPM_CHECK = 'schema = "agent"\nschemaVersion = 3\nvault-addr = "http://127.0.0.1:8200"\n[import]\ncatalog = "/root/catalog.json"\npolicy = "/root/policy.json"\nbundle = "/root/b-tpm.sealed"\n[unlock]\nunlock-tpm = true\n'
    TOML_RECOV = 'schema = "agent"\nschemaVersion = 3\nvault-addr = "http://127.0.0.1:8200"\n[import]\ncatalog = "/root/catalog.json"\npolicy = "/root/policy.json"\nbundle = "/root/b-recov.sealed"\n[unlock]\nunlock-tpm = true\nunlock-passphrase-file = "/root/pass"\nunlock-passphrase-no-wipe = true\n'

    def put(node, path, content):
        blob = base64.b64encode(content.encode("utf-8")).decode("ascii")
        node.succeed(f"echo '{blob}' | base64 -d > {path}")

    def provision_backend(node):
        # Start an in-memory OpenBao dev server ad hoc, mirroring
        # scripts/prefill-test-store.sh. A bare systemd unit unseals but
        # then exits/restart-loops without a login environment; launching
        # `bao -dev` through the driver's root shell (full PATH + a `sh`
        # for openbao's config-path expansion) and polling `bao status`
        # is the reliable, harness-matching path. Re-runnable: a prior
        # in-VM bao (e.g. before a reboot) is gone, so the pkill is just
        # defensive, and the fresh dev server is auto-unsealed.
        node.execute("pkill -INT -x bao 2>/dev/null; true")
        node.execute(
            "bao server -dev -dev-root-token-id=root "
            "-dev-listen-address=127.0.0.1:8200 "
            "</dev/null >/root/bao.log 2>&1 &"
        )
        node.wait_until_succeeds(
            "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root bao status >/dev/null",
            timeout=90,
        )
        node.succeed(
            "VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=root "
            "bao secrets enable transit >/dev/null 2>&1 || true"
        )

    def start_broker(node, logfile):
        node.execute("systemctl reset-failed basil-broker 2>/dev/null; true")
        node.succeed("rm -f /root/basil.sock")
        node.succeed(f": > {logfile}")
        node.succeed(
            "systemd-run --unit=basil-broker "
            "--setenv=RUST_LOG=info --setenv=NO_COLOR=1 "
            f"-p StandardOutput=append:{logfile} "
            f"-p StandardError=append:{logfile} "
            f"{basil} agent -c /root/agent-tpm.toml"
        )
        # Bounded wait that fast-fails if the broker exits instead of
        # binding the socket (don't block the full timeout on a crash).
        rc, _ = node.execute(
            "timeout 60 sh -c '"
            "while ! test -S /root/basil.sock; do "
            "systemctl is-active --quiet basil-broker || exit 7; "
            "sleep 0.5; done'"
        )
        if rc != 0:
            print("=== broker logfile ===")
            print(node.execute(f"cat {logfile}")[1])
            print("=== journalctl -u basil-broker ===")
            print(node.execute("journalctl -u basil-broker --no-pager -o cat")[1])
            raise Exception(f"broker failed to bind socket (rc={rc})")

    def serve_proof(node, tag):
        msg = f"tpm-unlock-serve-{tag}"
        sig = node.succeed(
            f"{basil} --socket /root/basil.sock sign --key-id example.signing_key '{msg}'"
        ).strip()
        node.succeed(
            f"{basil} --socket /root/basil.sock verify --key-id example.signing_key "
            f"--signature {sig} '{msg}'"
        )
        # A signature over a DIFFERENT message must verify false (exit 1).
        node.fail(
            f"{basil} --socket /root/basil.sock verify --key-id example.signing_key "
            f"--signature {sig} 'tampered-{tag}'"
        )

    start_all()
    tpmnode.wait_for_unit("multi-user.target")
    notpm.wait_for_unit("multi-user.target")
    othertpm.wait_for_unit("multi-user.target")

    with subtest("phase-1: emulated TPM present + baked-in basil runs"):
        # tpm_available() is exactly this device-path probe.
        tpmnode.succeed("test -e /dev/tpmrm0")
        tpmnode.succeed(f"{basil} --version")

    with subtest("scenario A: seal a TPM-only + a TPM+recovery bundle"):
        provision_backend(tpmnode)
        put(tpmnode, "/root/catalog.json", CATALOG_A)
        put(tpmnode, "/root/policy.json", POLICY_A)
        put(tpmnode, "/root/agent-tpm.toml", TOML_TPM)
        tpmnode.succeed("printf 'recov-not-a-secret' > /root/pass")
        # TPM-only slot: a fresh 32-byte slot key TPM2_Sealed under a PCR
        # policy; the master KEK AES-256-GCM-wrapped under it.
        tpmnode.succeed("printf root > /root/token && chmod 600 /root/token")
        tpmnode.succeed(
            f"{basil} bundle create /root/b-tpm.sealed --slot tpm "
            "--backend id=primary,type=openbao,token-file=/root/token"
        )
        tpmnode.succeed("test -s /root/b-tpm.sealed")
        # A second bundle that ALSO carries a passphrase recovery slot.
        tpmnode.succeed(
            f"{basil} bundle create /root/b-recov.sealed --slot tpm "
            "--slot passphrase:file=/root/pass "
            "--backend id=primary,type=openbao,token-file=/root/token"
        )
        tpmnode.succeed("test -s /root/b-recov.sealed")

    with subtest("scenario A: on-disk bundle exposes no cleartext slot key"):
        tpmnode.succeed("head -c 9 /root/b-tpm.sealed | grep -q BASILBDL")
        tpmnode.succeed("grep -aq '\"kind\":\"tpm\"' /root/b-tpm.sealed")
        tpmnode.succeed("grep -aq '\"pcrs\":' /root/b-tpm.sealed")
        # Only the TPM-sealed private blob + AEAD-wrapped KEK are present;
        # no cleartext slot-key/plaintext field is ever serialized.
        tpmnode.fail("grep -aiqE 'slot[_-]?key|cleartext|plaintext' /root/b-tpm.sealed")

    with subtest("scenario A: TPM auto-unlock + sign/verify (pre-reboot)"):
        start_broker(tpmnode, "/root/broker-a.log")
        # The ONLY enabled slot is TPM, with no operator secret, so the
        # only way the bundle opened is a TPM2_Unseal.
        tpmnode.succeed("grep -q 'sealed bundle unlocked' /root/broker-a.log")
        tpmnode.succeed("grep -q method=tpm /root/broker-a.log")
        serve_proof(tpmnode, "pre-reboot")

    with subtest("transfer the sealed bundles to the no-TPM / foreign-TPM nodes"):
        b_tpm = tpmnode.succeed("base64 -w0 /root/b-tpm.sealed").strip()
        b_recov = tpmnode.succeed("base64 -w0 /root/b-recov.sealed").strip()
        for n in [notpm, othertpm]:
            n.succeed(f"echo '{b_tpm}' | base64 -d > /root/b-tpm.sealed")
        notpm.succeed(f"echo '{b_recov}' | base64 -d > /root/b-recov.sealed")

    with subtest("scenario A: reboot reusing TPM state -> auto-unlock + serve"):
        # Full guest restart reusing the SAME persisted swtpm state dir.
        tpmnode.shutdown()
        tpmnode.start()
        tpmnode.wait_for_unit("multi-user.target")
        tpmnode.succeed("test -e /dev/tpmrm0")
        # The sealed bundle survived the reboot on disk.
        tpmnode.succeed("test -s /root/b-tpm.sealed")
        provision_backend(tpmnode)
        start_broker(tpmnode, "/root/broker-b.log")
        tpmnode.succeed("grep -q 'sealed bundle unlocked' /root/broker-b.log")
        tpmnode.succeed("grep -q method=tpm /root/broker-b.log")
        serve_proof(tpmnode, "post-reboot")

    with subtest("scenario B: PCR mismatch fails closed (tpmnode)"):
        # Perturb a sealing-policy PCR; the running broker is unaffected
        # (it unsealed at startup), but a fresh unseal must fail closed.
        tpmnode.succeed(
            "tpm2_pcrextend 7:sha256=$(echo basil-pcr-mismatch | sha256sum | cut -d' ' -f1)"
        )
        tpmnode.fail(
            f"RUST_LOG=info {basil} doctor -c /root/agent-tpm.toml >/root/pcr.log 2>&1"
        )
        tpmnode.fail("grep -q 'sealed bundle unlocked' /root/pcr.log")

    with subtest("scenario B: no-TPM fails closed; passphrase recovery opens (notpm)"):
        notpm.succeed("test ! -e /dev/tpmrm0")
        put(notpm, "/root/catalog.json", CATALOG_ZERO)
        put(notpm, "/root/policy.json", POLICY_ZERO)
        put(notpm, "/root/agent-tpm.toml", TOML_TPM_CHECK)
        put(notpm, "/root/agent-recov.toml", TOML_RECOV)
        notpm.succeed("printf 'recov-not-a-secret' > /root/pass")
        # TPM-only bundle, no TPM, no recovery slot -> fail closed.
        notpm.fail(
            f"RUST_LOG=info {basil} doctor -c /root/agent-tpm.toml >/root/tpmonly.log 2>&1"
        )
        notpm.fail("grep -q 'sealed bundle unlocked' /root/tpmonly.log")
        # The recovery bundle's passphrase slot opens it when no TPM exists.
        notpm.succeed(
            f"RUST_LOG=info {basil} doctor -c /root/agent-recov.toml >/root/recov.log 2>&1"
        )
        notpm.succeed("grep -q 'sealed bundle unlocked' /root/recov.log")
        # No TPM on this node, so the ONLY slot that can open the
        # tpm+passphrase recovery bundle is the passphrase slot (the
        # tpm-only bundle above fails closed on this same node). The
        # stable `unlock slot opened` message from seal::open_bundle
        # confirms a slot recovered the KEK; in the no-TPM topology that
        # slot is necessarily the passphrase one. (We match the message,
        # not the structured `method=` field, whose rendering differs
        # between the agent and `doctor` log formatters.)
        print("recov.log:\n" + notpm.execute("cat /root/recov.log")[1])
        notpm.succeed("grep -q 'unlock slot opened' /root/recov.log")

    with subtest("scenario B: different-TPM fails closed (othertpm)"):
        othertpm.succeed("test -e /dev/tpmrm0")
        put(othertpm, "/root/catalog.json", CATALOG_ZERO)
        put(othertpm, "/root/policy.json", POLICY_ZERO)
        put(othertpm, "/root/agent-tpm.toml", TOML_TPM_CHECK)
        # The tpmnode-sealed blob cannot be loaded/unsealed by a foreign
        # TPM hierarchy -> fail closed (does-not-move-with-a-disk-image).
        othertpm.fail(
            f"RUST_LOG=info {basil} doctor -c /root/agent-tpm.toml >/root/foreign.log 2>&1"
        )
        othertpm.fail("grep -q 'sealed bundle unlocked' /root/foreign.log")
  '';
}
