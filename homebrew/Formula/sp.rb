class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.7.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.1/sp-darwin-arm64"
      sha256 "2cb79a74b41821c3adc47752136ba55ae0202e8dcc98b3ac35158b7bb777c32c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.1/sp-darwin-amd64"
      sha256 "c483c025307fdca2c14f6e2b4b698e7bebe4105f42bae70dfac6cdbfb386cb34"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.1/sp-linux-arm64"
      sha256 "8a251a3a7f7ff42990fbc0b172c4e4bdcac76b000cc1ed25d410775b56496296"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.1/sp-linux-amd64"
      sha256 "7a7dc42b9c1432d157110bb5599d2c9b97038206f62447286f5337a62e76d5de"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
