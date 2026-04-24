class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mrthoabby/serverpilot/releases/download/v1.0.0/sp-darwin-arm64"
      sha256 "0ac2960dcd1d2454ff1a50752fa55f566b550ad225f9d7fe894190236eb55bed"
    else
      url "https://github.com/mrthoabby/serverpilot/releases/download/v1.0.0/sp-darwin-amd64"
      sha256 "8be71caf0eabd13356442e3b2e5e68d15959b1c1fef2d9ad005299ae618e8674"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/mrthoabby/serverpilot/releases/download/v1.0.0/sp-linux-arm64"
      sha256 "1a52654534361f254cfd59c007ea92113af327a7bbd1659e01b59ff8e50156ed"
    else
      url "https://github.com/mrthoabby/serverpilot/releases/download/v1.0.0/sp-linux-amd64"
      sha256 "e11889228c350739ddf999fc6c90a28957d007f6ea4e33ae0437ffda3c83d82f"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
