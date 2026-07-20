class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.8.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.8.0/sp-darwin-arm64"
      sha256 "d34e99a08658c81867d9bebe42d483670b60a43d081b47d92514b62b96f68610"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.8.0/sp-darwin-amd64"
      sha256 "a723532758d66293a3cdb2b8f66b6dd9dd4c086760b8cd2e3943f29b6d584ce7"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.8.0/sp-linux-arm64"
      sha256 "3960c4de18f74c2c8cc20461d238cece99f8c473a09908757bc7d7b8e1241c4a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.8.0/sp-linux-amd64"
      sha256 "ebd797663d0afe6943cbd81a3024dca3a8ed12a24245bde26ae3da94c6bd3586"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
