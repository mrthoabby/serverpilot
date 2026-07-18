class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.4.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.2/sp-darwin-arm64"
      sha256 "f80ce381d961662a42609decbb77a0281a0b1f1e3662097efd3643281cd5e6e1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.2/sp-darwin-amd64"
      sha256 "79d7636d046e9274d039da407f604a536cdf41ab762b8ff9078b42c73ce7684b"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.2/sp-linux-arm64"
      sha256 "1350f9b4ac7b223a997eeb17dcd8c7202bdb0ec7eaacb980c8032118cb73f9be"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.2/sp-linux-amd64"
      sha256 "bcad18cef5c742cfb0ecc8b4c1812b68a266eccf62c24cde7ffbaa44036218e1"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
