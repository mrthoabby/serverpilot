class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.6.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-darwin-arm64"
      sha256 "22becc850a9260838dd6505fc81f4c5e70435fbdad564f65dbd7f5630bd1d117"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-darwin-amd64"
      sha256 "2d23c93f33c20ae18b48e9180d16cfba9ef508ffd2fc81c4507f1cfc4c1af39b"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-linux-arm64"
      sha256 "1ebb83dcc956355ed9784f117c726409fd8d84c125bebbbc3c7464dcb47a0d7a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-linux-amd64"
      sha256 "61c7b048f1cf6196cd174c9e10dfb398946242fe94d669ddf6738ddb8b2cc68e"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
