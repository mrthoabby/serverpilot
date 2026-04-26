class SpAT1.9.0 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.9.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.9.0/sp-darwin-arm64"
      sha256 "f8f6b4ca1ac54be8004f20beb3bfd34292d093182a0d2eacebd8f39ad16d91d0"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.9.0/sp-darwin-amd64"
      sha256 "16771868d40be75e608f2e5e8d340b0817bb2577422260a6f36ed044939d0f8d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.9.0/sp-linux-arm64"
      sha256 "87ae66bf034a5497fd7999efadc9232f0568c78fc29f0c76d6036b66957ac411"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.9.0/sp-linux-amd64"
      sha256 "19e75e9f7d40c46279cbd4a5871c1b7014477705c2664620210bb7c487b84370"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
