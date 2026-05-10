class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.4.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.4.0/sp-darwin-arm64"
      sha256 "7a0ced592cbb2d2e14948295c3dc38b274352136d82a36ddb52ee0c582c876ce"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.4.0/sp-darwin-amd64"
      sha256 "c781889a80c99df00e6ab82b2e30e94fc06e1b4925cc3634966af9ed4cf47d78"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.4.0/sp-linux-arm64"
      sha256 "c22156f97d8a113db3b093029eec69cbdb850abae5cb5c680dae2f1540616840"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.4.0/sp-linux-amd64"
      sha256 "659b0f3002e95423fd88df88da2745a8f156b16232663570422a6f3d231a97e6"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
