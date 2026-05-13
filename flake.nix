{
  description = "A suite for testing compiler submissions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane.url = "github:ipetkov/crane";
    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      gitignore,
      nixpkgs,
      crane,
    }:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          craneLib = crane.mkLib pkgs;
          inherit (gitignore.lib) gitignoreSource;
        in
        rec {
          backend = craneLib.buildPackage {
            pname = "backend";
            src = gitignoreSource ./backend;
          };
          frontend = pkgs.stdenv.mkDerivation (finalAttrs: {
            pname = "frontend";
            version = backend.version;

            src = gitignoreSource ./frontend;

            nativeBuildInputs = [
              pkgs.nodejs
              pkgs.pnpmConfigHook
              pkgs.pnpm
            ];

            buildPhase = ''
              runHook preBuild
              pnpm build
              runHook postBuild
            '';

            installPhase = ''
              runHook preInstall
              mkdir $out
              cp -r dist/* $out
              runHook postInstall
            '';

            pnpmDeps = pkgs.fetchPnpmDeps {
              inherit (finalAttrs) pname version src;
              fetcherVersion = 2;
              hash = "sha256-XBHnTjwxqHpVwslKU8A6oWFxlo1lUfm6QQ31aFOmHuk=";
            };
          });
          frontend-docker =
            let
              caddy-config = pkgs.writeText "Caddyfile" ''
                :80 {
                  try_files {path} /
                  encode gzip
                  root * ${frontend}
                  file_server
                }
              '';
            in
            pkgs.dockerTools.buildLayeredImage {
              name = "frontend";
              tag = backend.version;

              config = {
                Entrypoint = [
                  "${pkgs.caddy}/bin/caddy"
                  "run"
                  "--adapter"
                  "caddyfile"
                  "--config"
                  caddy-config
                ];

                Expose = {
                  "80/tcp" = { };
                };
              };
            };
        }
      );

      formatter.x86_64-linux = nixpkgs.legacyPackages.x86_64-linux.nixfmt-rfc-style;
    };
}
