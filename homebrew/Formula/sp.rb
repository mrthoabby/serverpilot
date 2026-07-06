class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.28"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.28/sp-darwin-arm64"
      sha256 "d7927e28f75e11b1bc9ff2b6cdb0f400da6ff9850d628350c7895596d310f03b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.28/sp-darwin-amd64"
      sha256 "c4348bced47d785369d80b2a530c8c2f4dc722b2292eabad249a690e6d37b981"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.28/sp-linux-arm64"
      sha256 "088b0aabd94e6a2000ca933e58fdd72377b7db647934b79c1db6754c93b992a4"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.28/sp-linux-amd64"
      sha256 "cd426e8a0fd589400746b654f5b0a6408722edac0edea9bfa6a07f1951b9d605"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
