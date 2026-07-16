class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.0.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.1/sp-darwin-arm64"
      sha256 "f7086a5eeb36d2a0ef11c26c70f0d7151d285785002e9b984d6bdb767f83c7b7"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.1/sp-darwin-amd64"
      sha256 "5860afde23265b17f2bf60f10bd20736814005eda9db791fe373152e4a423482"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.1/sp-linux-arm64"
      sha256 "3c4eee4e3dba1423551085c71b3e7525d63b67c076fb98c951fee9ba143be1c9"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.1/sp-linux-amd64"
      sha256 "5b7b6d5d681059eabb0c4b7c9fcea69ce0af4741433e6df5aa50b604efd263cb"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
