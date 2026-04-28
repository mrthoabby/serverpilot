class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.2/sp-darwin-arm64"
      sha256 "1842a66da30a3c7c07504fed21fa77dbabd714fa93a028241d5bfc7e11a5efed"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.2/sp-darwin-amd64"
      sha256 "873777a3450d694f50537cc0d92307f848d4b729c16277c25cd75aeb6158129e"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.2/sp-linux-arm64"
      sha256 "faa0dd147a72e2835d0ec2694dbb9be83cc05c3de4783129074a3b4d1f17ac62"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.2/sp-linux-amd64"
      sha256 "9236624bcee8bba7e7beeaa663987427140378439c3d655e02fd92c9305e0400"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
