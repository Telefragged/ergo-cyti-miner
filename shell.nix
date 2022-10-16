{}:
let
  moz_overlay = import (builtins.fetchTarball https://github.com/mozilla/nixpkgs-mozilla/archive/master.tar.gz);
  pkgs = import <nixpkgs> { overlays = [ moz_overlay ]; };
  rust-channel = pkgs.latest.rustChannels.nightly;
  rust = rust-channel.rust;
  rust-src = rust-channel.rust-src;
in pkgs.mkShell {
  buildInputs = with pkgs; [
    rust
    openssl
    pkg-config
  ];

  RUST_SRC_PATH = "${rust-src}/lib/rustlib/src/rust/library";
}
