class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "3.4.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.4.0/sp-darwin-arm64"
      sha256 "5d747cb13092de4355bde5debf57b343129f409a1770fa1e114921ca894c6ccb"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.4.0/sp-darwin-amd64"
      sha256 "36e90474d450c2d5056b4af4b0685f236c6740e8801864269b13d09a3fcde97b"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.4.0/sp-linux-arm64"
      sha256 "cfa9d37a8707012bcc07bbf144838edbae1bb14c134b928c0e173bec94e4dde2"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.4.0/sp-linux-amd64"
      sha256 "f9ad6ec617498cee740d5d3da92f821c25f5cc5618adca261efb869e2aa118da"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
