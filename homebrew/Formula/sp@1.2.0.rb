class SpAT1.2.0 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0/sp-darwin-arm64"
      sha256 "79e3fc00be1110c5010384e3b5e8f881f9467898e88c24a6863829d66f518139"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0/sp-darwin-amd64"
      sha256 "1d4d11317fc257a1c763cd87fdb9949f6ccec5e9bc929a50f636677a3a32edff"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0/sp-linux-arm64"
      sha256 "a82f09ed1e60b6ec00886951715cef83dbe9c7496ae2d371b53309b81c37082d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0/sp-linux-amd64"
      sha256 "267bd1c6d1a74f4fb06bd1a2918c068010b87f0fad3b45640a1716e749146ef2"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
