class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.6.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-darwin-arm64"
      sha256 "ad377b18ab6cf667301bb539436725760459eeb1a38499e10897a533d607275e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-darwin-amd64"
      sha256 "7ce0bd28d46e98b12cc428b1dd99973c35d9af6ca832a26c3182926135ae2c94"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-linux-arm64"
      sha256 "dcba0de2dbd148cef0d104561d469171f2e45bf2fc06442039e1cc14014cc797"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-linux-amd64"
      sha256 "899ec950223e8f160c73a64f283c9f93837bc3b32717f59bf81a448a64392c1c"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
