class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.4.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.1/sp-darwin-arm64"
      sha256 "8f5ee84bd1c330fbf307412d34235f4f54411e8853d3baf206a885801bade956"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.1/sp-darwin-amd64"
      sha256 "9165e2aa82cfdcf610c89ba998a85cf584c740b85b7c175b8dfa97aba93b0663"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.1/sp-linux-arm64"
      sha256 "0625d7a0a7649fd70a4163760967af2d8adf66b076bab55af785f407bfa8cb44"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.1/sp-linux-amd64"
      sha256 "189ff7ddf582b0c15a1572c4f0f41fa1cc5059c77351bed9cea07290917fdd5f"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
