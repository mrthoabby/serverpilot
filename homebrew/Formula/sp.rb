class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.11.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.3/sp-darwin-arm64"
      sha256 "9fed89340b901eb2d9757967d7d2e3a5b2cd84476eecc2543f1d4051a874a716"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.3/sp-darwin-amd64"
      sha256 "9612fd1ccb4a0167061ac81ecaaef7f03dc71dc2bd1ea69010e3b6b06766d4a7"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.3/sp-linux-arm64"
      sha256 "657a6f43da4908387f08e1999fc0ab49d897606a2cce2441ebddcf356062bcf2"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.3/sp-linux-amd64"
      sha256 "2e577fe26d5a4c0e57a6a223deb3108e432508fc7325975e369e50cde92eddd9"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
