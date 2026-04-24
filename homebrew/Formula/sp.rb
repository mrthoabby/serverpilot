class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.0-alpha"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0-alpha/sp-darwin-arm64"
      sha256 "ff5c9bf2b30c68433b0b63c3e73a39230687e784f1b732a848abc97b294fc49b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0-alpha/sp-darwin-amd64"
      sha256 "fcfba29805ba28031aab15dcab18e87a5812b30c5397c08cb035372bc3e6f58b"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0-alpha/sp-linux-arm64"
      sha256 "34cf4258fe9eab94d4e53ef81325ae86141c870e06416a964ef2a9ad597ee573"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0-alpha/sp-linux-amd64"
      sha256 "edccb03bf64af767194a730697aa2782cfc5c84cd6995160f7b5b8bd26f0f3ae"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
