{ pkgs ? import <nixpkgs> {} }:

let
  dotnetCombined = with pkgs.dotnetCorePackages;
    combinePackages [
      sdk_8_0
      runtime_8_0
    ];
in
pkgs.mkShell {
  buildInputs = [
    dotnetCombined
    pkgs.omnisharp-roslyn
  ];

  shellHook = ''
    export DOTNET_ROOT="${dotnetCombined}"
    export PATH="$PATH:$HOME/.dotnet/tools"
    export DOTNET_CLI_TELEMETRY_OPTOUT=1
  '';
}
