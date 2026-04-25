class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0/sp-darwin-arm64"
      sha256 "ddd62f06cfec1b2a216d5cb498038e81d2fc86db0c0e58f16775a5d27ddc9a89"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0/sp-darwin-amd64"
      sha256 "fbc0c31d497bcf80e0de4eadf401eec4c1fe34bf97fe177bd14e0bb4f36b4ffd"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0/sp-linux-arm64"
      sha256 "151d48f1377c0de7275fe69f59b41a16ecb2aafe75bf6e876a5e3694aa4d35d6"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.0/sp-linux-amd64"
      sha256 "015ac23a46c9a5d72ec20539ccb1eb09c22412e3d759b751626010eb48da0684"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
