class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "3.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.0.0/sp-darwin-arm64"
      sha256 "47f421a5c089763683150de61ca9b467a261dd0c811632b70393d52099b8413c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.0.0/sp-darwin-amd64"
      sha256 "f7beeca331f4b3f5b22554af07fcc20ff2e97c7a05fbe195f1a7421ab91725fd"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.0.0/sp-linux-arm64"
      sha256 "ac8ae5c88c0f1845f37a556a575e88693c79aa5b98640e52464e7056d73af4b1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.0.0/sp-linux-amd64"
      sha256 "48eca45bde068b7f0faffafcbe04d13aac2167c93efc4940a68fb3dcd0a5961e"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
