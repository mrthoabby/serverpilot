class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-darwin-arm64"
      sha256 "771e342a6eb64189f724b2bd5d3ca5588f4f6a78887d3a866dea3743e205aa86"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-darwin-amd64"
      sha256 "18877a75aeaa49aa0d02bce3e441b1ecc4d9a8ce509f71ed991a2010fcd0efea"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-linux-arm64"
      sha256 "df802054c4278e13848c5528b03f0e004851bfe3fabd8d507a7771a886726595"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-linux-amd64"
      sha256 "89256932fb5af9f0a3393de4a2c2273d6c44eb1d6bd878dfae9f362b16b08dc8"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
