class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.2/sp-darwin-arm64"
      sha256 "436bfbc26e3ce3d59a3f0125910f7c984a091657457f3c62dd35e943cef1f4f6"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.2/sp-darwin-amd64"
      sha256 "1ea1ac2e4bf547dc18c359b19478357a4b9c5c2bf8da31bcb83d661c97fa7f64"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.2/sp-linux-arm64"
      sha256 "5c1f3c163344f7fd811be2def730a5804d1d2957585139f7bbaa64ec6eb3704a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.2/sp-linux-amd64"
      sha256 "3641539cc7c2989f4e8b9d2eb982738642b9fa1399492ca9cf95d4a8db680b72"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
