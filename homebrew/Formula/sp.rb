class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1/sp-darwin-arm64"
      sha256 "00e4caab956a4429d721f4d7b799e9b27de037c99e1aa5fd5b82cfdafa144722"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1/sp-darwin-amd64"
      sha256 "c6d76efb9aeb8f508d8073fa34440670083e0b6195b551d03892926d9b2266ed"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1/sp-linux-arm64"
      sha256 "29f189a4328cf69b5e9078ded746055d0c09c6e9cd82586b19a21a9c21429d8b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1/sp-linux-amd64"
      sha256 "bfa2d7350ee3c215c1a82bb57fcd80a71af648751d29858d687be482855dcaf4"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
