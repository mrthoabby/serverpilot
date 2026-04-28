class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0/sp-darwin-arm64"
      sha256 "a0b3479eec769cd7d62e4771e288a74ce0eeb9ff47040c85167451df34435ad0"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0/sp-darwin-amd64"
      sha256 "c216359979eaab501200ed8b043d0ef9c326bc283e286c1065a154d16516649f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0/sp-linux-arm64"
      sha256 "025503c355e1d7b5036c99fcc6aa4c07ff1604585d8df69084c8022d2f33596b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0/sp-linux-amd64"
      sha256 "4b936dd8fe72a969e28b19fc485872557eb3bc4c1e2d16b39db765b096c2c028"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
