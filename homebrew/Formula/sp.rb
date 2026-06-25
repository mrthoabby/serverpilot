class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-darwin-arm64"
      sha256 "7f2f718a355e067cc6bc711a410c602af2e19329d77c6c4b8284c79e95323bde"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-darwin-amd64"
      sha256 "d9995efc0330eec1c16f17c3a6feb876f8bdd37e360c23868c049aa63a9d6fc0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-linux-arm64"
      sha256 "579cd4dc871939d128c90c1306b3b1b43be638abcff103f15865fb3a997aec39"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-linux-amd64"
      sha256 "680912eb5b0ab70ce78ea7fde17374775f0708d4c18b061fb7f936c46a236c7a"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
