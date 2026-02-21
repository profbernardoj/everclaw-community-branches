# Nix flake overlay for adding EverClaw proxy as a service
#
# Add to your NullClaw flake.nix:
#   inputs.null-everclaw.url = "github:EverClaw/everclaw?dir=NullClaw";
#
# STATUS: Scaffold — community TODO to make this a proper Nix module.
# This shows the general pattern for integrating the proxy via Nix.

{ pkgs, ... }:

{
  # EverClaw proxy as a systemd user service
  systemd.user.services.everclaw-proxy = {
    description = "EverClaw Morpheus Proxy";
    after = [ "network.target" ];
    wantedBy = [ "default.target" ];

    serviceConfig = {
      Type = "simple";
      ExecStart = "${pkgs.nodejs}/bin/node /home/user/.everclaw/scripts/morpheus-proxy.mjs";
      Restart = "always";
      RestartSec = 5;
      Environment = "NODE_ENV=production";
    };
  };

  # Ensure Node.js is available
  environment.systemPackages = with pkgs; [
    nodejs
    git
    curl
  ];
}
