class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.5.6"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.6/sp-darwin-arm64"
      sha256 "cde1c50541ebc00efcc92bfbad6ee245e40ac26cb524975a7122fa57920571a5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.6/sp-darwin-amd64"
      sha256 "e6588e714db45995386e438b2f53a2664a4ec4ac3b66c7ffbda9999448ce4162"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.6/sp-linux-arm64"
      sha256 "8d0806b5f5242ae767c2407d0c01d8eb098ecb5a1299f48211c35d4948c8d619"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.6/sp-linux-amd64"
      sha256 "426dca1c864e1ccf6639ccbc013ae676ba8ef1d3ed7d8a919123562fae7934e2"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
