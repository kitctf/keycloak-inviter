{
  description = "A suite for testing compiler submissions";

  inputs = {
    naersk.url = "github:nix-community/naersk";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    naersk.inputs.nixpkgs.follows = "nixpkgs";
    gitignore.url = "github:hercules-ci/gitignore.nix";
    gitignore.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      gitignore,
      nixpkgs,
      naersk,
    }:
    let
      forAllSystems = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          naersk' = pkgs.callPackage naersk { };
          inherit (gitignore.lib) gitignoreSource;
        in
        rec {
          backend = naersk'.buildPackage {
            src = gitignoreSource ./backend;
          };
          frontend = pkgs.stdenv.mkDerivation (finalAttrs: {
            pname = "frontend";
            version = backend.version;

            src = gitignoreSource ./frontend;

            nativeBuildInputs = [
              pkgs.nodejs
              pkgs.pnpm_9.configHook
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

            pnpmDeps = pkgs.pnpm_9.fetchDeps {
              inherit (finalAttrs) pname version src;
              fetcherVersion = 1;
              hash = "sha256-MNpEmME8gymAkMNFfLZMO2bu9CQCktNhyN7ADWe71G0=";
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
