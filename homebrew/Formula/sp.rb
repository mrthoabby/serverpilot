class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.7.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.2/sp-darwin-arm64"
      sha256 "78abb674f2c2c0c02d4fc56dac384253e3557cfdd9e6f2e1e14a9ee7e75190ca"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.2/sp-darwin-amd64"
      sha256 "ce7f49d65fa907e9a0c2785b36d563d78d86ef47616e87e81b81ba3281f91657"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.2/sp-linux-arm64"
      sha256 "193b949212e74df83541f3a6eca758a8310b1580a40f70a0fc02de66277bd62c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.2/sp-linux-amd64"
      sha256 "a6df176cbea99b14acab09fc9e405f170d54323ce056025332adb989dd837080"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
