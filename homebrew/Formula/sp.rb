class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.6"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.6/sp-darwin-arm64"
      sha256 "6dfbc124af55149480ef381720d324cbbde56c2b23e6f40751b7aa49bf10b4be"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.6/sp-darwin-amd64"
      sha256 "03aa43bafe1df0f075d0043e39201ec78913e3d53239e3a1b2121b50722476aa"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.6/sp-linux-arm64"
      sha256 "337feaff089de0054753d43f5a7e7c034316bbe301751f9e610d111489244959"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.6/sp-linux-amd64"
      sha256 "b8689af2c9e82f16206adacfc4eb410447a947a310a6b3a5af86052c8d454cbe"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
