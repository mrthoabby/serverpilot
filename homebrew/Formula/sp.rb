class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.7.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.0/sp-darwin-arm64"
      sha256 "28d473f729d5a86bc127abafc3ffd3fd901f9b1b5d116d2b967962492a133a5e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.0/sp-darwin-amd64"
      sha256 "ad35306db0cd3259f825ff6614493c0a05d732a1bfbdf6d9038c129d33ada90d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.0/sp-linux-arm64"
      sha256 "c16de482784aeb67b886c115bb65c60cb940d1922d14455e6562b7a2ce6cc283"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.0/sp-linux-amd64"
      sha256 "12efce7c3045a102dbda2a9490ee5c0ae2a02381101c6f824718b2c749a8b13c"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
