class SpAT1.0.1 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1/sp-darwin-arm64"
      sha256 "3b0d2770e5e9de1cb9803d518c2f37db96ae55acb3ccb70c414ee97693cd4f11"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1/sp-darwin-amd64"
      sha256 "44f7e0b90552023ff0b82c86185eb28d670c55a0bb8f94c28c4ed7e21b1e4b28"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1/sp-linux-arm64"
      sha256 "7c14125cefa4df02eae9b532fac3c08d798c3f517d83239c254229fc5e7ceb45"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1/sp-linux-amd64"
      sha256 "9fd7da1a54bcabd3836f7686fa1aa5ce61da28c2c06166344bca6265618a17a9"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
