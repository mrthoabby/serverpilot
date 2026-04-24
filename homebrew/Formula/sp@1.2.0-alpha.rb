class SpAT1.2.0-alpha < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.2.0-alpha"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0-alpha/sp-darwin-arm64"
      sha256 "0114cc23fea35688278df300eb5e3ebd5240961254a6f755db5f7a7b7ca9b2da"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0-alpha/sp-darwin-amd64"
      sha256 "ac6d0923159943ca7ddc0a08e9b3266678284d8ce949b335604170246eda7f06"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0-alpha/sp-linux-arm64"
      sha256 "0e647c397632c9ff8c9163a1378676df8cbe4778d1ecd49064ef98926a3a7e84"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0-alpha/sp-linux-amd64"
      sha256 "2269c38b55da36d64d38e43ad3d93c8cc0ba287cfa41e70562995e7e9e35574f"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
