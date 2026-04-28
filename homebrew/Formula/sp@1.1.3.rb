class SpAT1.1.3 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.3/sp-darwin-arm64"
      sha256 "e4b185f15a49580cb5112583736921ac1912b756dec1dcbdee698cbe77f518de"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.3/sp-darwin-amd64"
      sha256 "b3f5c986556cbe47db703c953e3a717143f711b306ae8c2e87b8a3f63c5c30e6"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.3/sp-linux-arm64"
      sha256 "a0feaf905e0f994ff6b1fcf7fc60294884d82906a0016c9cf4bba4be2b38dec2"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.3/sp-linux-amd64"
      sha256 "6acff1ba8bac85f3a860936bd135cdc46d67de8c798a202bb9b41ca6894495db"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
