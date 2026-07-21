class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.9.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.2/sp-darwin-arm64"
      sha256 "e9d108dc0ee4b6e7e92106b0dfccbf599b97b4d9f917c1ef3c0ac881565a986c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.2/sp-darwin-amd64"
      sha256 "f885eed3eb44bf65c5ffb42be790094b530d59ff88b2cde8b6fc7cdf01e48259"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.2/sp-linux-arm64"
      sha256 "954ed83e1ffe2dcee760464fca4ddb97ef233a786d016201209fca461dad3ed1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.2/sp-linux-amd64"
      sha256 "e00046691e552aeb02cbd87a5e0e4032427acafb804afceff8821afc9e122779"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
