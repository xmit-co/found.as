{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    xmit = {
      url = "github:xmit-co/xmit";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      flake-utils,
      nixpkgs,
      xmit,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            nodejs
            pnpm
            resvg
            inter
            ffmpeg
            xmit.packages.${system}.default
          ];
          # Deterministic font for the og:image rasterizer (publish.mjs). Any
          # other family is fetched on demand from cc.me/fonts rather than baked.
          INTER_FONT = "${pkgs.inter}/share/fonts/truetype/InterVariable.ttf";
        };
      }
    );
}
