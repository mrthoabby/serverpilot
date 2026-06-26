class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.7"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.7/sp-darwin-arm64"
      sha256 "f1650dbd6631449f75495ae2b847555e2e58b6efbb3a599b11767235c25943d7"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.7/sp-darwin-amd64"
      sha256 "279880db97b3da4acad7edae8dd1817d5f77683c13a5eb75a4f50c12a96e1a19"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.7/sp-linux-arm64"
      sha256 "06f084b3195f56a4c88c94114a99d1a9c330807ffa346c1b0c75beedb4d725ff"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.7/sp-linux-amd64"
      sha256 "4f745981e9e674de17e6998088abb84d2ec5410b9cb0d3411f7b5ab5a774f5c8"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
