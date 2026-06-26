class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.18"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.18/sp-darwin-arm64"
      sha256 "127d84195d3be3dcf203044c0284e2258494bca10c4b41e9030ded42ceef4eda"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.18/sp-darwin-amd64"
      sha256 "19bb838aa3fe1791355be8272fb0c27291afefc9eba8ee6fba3ab74c135893d8"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.18/sp-linux-arm64"
      sha256 "b9f5f66fe98a0b7e7609703dae9a2abe3ccc101601cca4d837bce3c15cf7add3"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.18/sp-linux-amd64"
      sha256 "f8d75b8f08d410154c9553db358b429ae7de707b9730d50811e1b295caefb870"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
