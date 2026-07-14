# SPDX-FileCopyrightText: 2026 OpenBasil Contributors
#
# SPDX-License-Identifier: Apache-2.0

{ pkgs, basil }:

let
  common =
    { lib, ... }:
    {
      imports = [ ../basil-agent.nix ];

      virtualisation.memorySize = 1024;
      environment.systemPackages = [ basil ];
      environment.etc."basil/doctor-quota.toml".text = ''
        catalog = "/root/missing-catalog.json"
        policy = "/root/missing-policy.json"
        bundle = "/root/missing-bundle.sealed"
        socket = "/run/basil-doctor.sock"

        [logging.journald]
        enable = false
      '';

      services.basil = {
        enable = true;
        bundle = pkgs.writeText "basil-doctor-empty-bundle" "";
        settings.package = basil;
      };

      # The module must be enabled for its sysctl policy, but this focused test
      # drives only the real doctor CLI and does not need a serving broker.
      systemd.services.basil-agent.wantedBy = lib.mkForce [ ];
    };
in
pkgs.testers.nixosTest {
  name = "basil-rootless-keyring-quota";

  nodes.default = common;

  nodes.low =
    { ... }:
    {
      imports = [ common ];
      services.basil.raiseRootlessKeyringQuotas = false;
      boot.kernel.sysctl = {
        "kernel.keys.maxkeys" = 200;
        "kernel.keys.maxbytes" = 20000;
      };
    };

  nodes.overridden =
    { ... }:
    {
      imports = [ common ];
      boot.kernel.sysctl = {
        "kernel.keys.maxkeys" = 4000;
        "kernel.keys.maxbytes" = 4000000;
      };
    };

  testScript = ''
    import json

    basil = "/run/current-system/sw/bin/basil"
    config = "/etc/basil/doctor-quota.toml"

    def quota_row(node):
        rc, output = node.execute(
            f"{basil} doctor --config {config} --json "
            "--rootless-expected-containers 1000"
        )
        # The deliberately absent catalog/bundle make unrelated doctor rows
        # fatal; the JSON document is still emitted before the clean exit 1.
        assert rc == 1, (rc, output)
        document = json.loads(output)
        rows = [
            row for row in document["checks"]
            if row["name"] == "rootless_keyring_quota"
        ]
        assert len(rows) == 1, document
        return rows[0]

    start_all()
    for node in [default, low, overridden]:
        node.wait_for_unit("multi-user.target")

    with subtest("module defaults support 1000 rootless containers"):
        default.succeed("test $(cat /proc/sys/kernel/keys/maxkeys) -eq 2000")
        default.succeed("test $(cat /proc/sys/kernel/keys/maxbytes) -eq 2000000")
        row = quota_row(default)
        assert row["status"] == "ok", row

    with subtest("disabled module option leaves an explicitly low host warning"):
        low.succeed("test $(cat /proc/sys/kernel/keys/maxkeys) -eq 200")
        low.succeed("test $(cat /proc/sys/kernel/keys/maxbytes) -eq 20000")
        row = quota_row(low)
        assert row["status"] == "warn", row
        assert (
            "sudo sysctl -w kernel.keys.maxkeys=2000 "
            "kernel.keys.maxbytes=2000000"
        ) in row["remediation"], row

    with subtest("higher explicit operator sysctls override defaults and pass"):
        overridden.succeed("test $(cat /proc/sys/kernel/keys/maxkeys) -eq 4000")
        overridden.succeed("test $(cat /proc/sys/kernel/keys/maxbytes) -eq 4000000")
        row = quota_row(overridden)
        assert row["status"] == "ok", row
  '';
}
