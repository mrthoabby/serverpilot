class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.17"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.17/sp-darwin-arm64"
      sha256 "ac217e971c877662edfd38ee6d76fadfab97dda8f8b93334b460cf86e91277f3"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.17/sp-darwin-amd64"
      sha256 "1e352983b068b4196b1f2b6b490494c5ba1e6220ac5968667a0e5b24f3fd3eca"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.17/sp-linux-arm64"
      sha256 "edd9d46b0cfe394df813fb0a6c079a2988a6432aeab46ee73bdd1fb056cb890f"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.17/sp-linux-amd64"
      sha256 "e7a8e3bb838e7e841ed4e9389fec459eadc47bd37fce9730fc6214cae4d1226f"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
