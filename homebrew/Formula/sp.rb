class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.24"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.24/sp-darwin-arm64"
      sha256 "f17715e7aedaadee813087fd8c79bb092ef6eac43dca49765e67b57e6316b16f"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.24/sp-darwin-amd64"
      sha256 "261dcbe630267c543d98b090dd861ddc0e72ca543eb2c533075e55896c48acb8"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.24/sp-linux-arm64"
      sha256 "56cf0bd138b34a355e14862d42b2d9e13a91ce66d79f5593d90ca43b49092740"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.24/sp-linux-amd64"
      sha256 "d3159122e76b2aaedee5298933feb3006365f7ca0da52cd12a1497ce55dbb3f8"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
