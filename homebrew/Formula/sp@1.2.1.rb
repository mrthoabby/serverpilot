class SpAT1.2.1 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.2.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.1/sp-darwin-arm64"
      sha256 "32df12c15220417bd6ae211fee4f6a9baa53dd97c323c2b01fe60276607238b5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.1/sp-darwin-amd64"
      sha256 "c38a4477348b6df94fa27daaef009c5f070202b9d209a125debad66eed560da2"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.1/sp-linux-arm64"
      sha256 "a0427f983a20f5acd6a4394b9e02882ccbac932e58ef3d3930993cd11d41c9aa"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.1/sp-linux-amd64"
      sha256 "9b65ceb07fabc76996b7c1059aae313c7a43856bf22187603c96ec06c43205a9"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
