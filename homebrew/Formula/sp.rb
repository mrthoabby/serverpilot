class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.12"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.12/sp-darwin-arm64"
      sha256 "d3f1f058b6ba93117430cbadd5c5fe9bfb21b63c2c53d5059163681b5e819660"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.12/sp-darwin-amd64"
      sha256 "338bcacdf36e7b6b47d26de7b10a42dcb2927f18d0718113cb7a16de157268ce"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.12/sp-linux-arm64"
      sha256 "6627df47c7f19c6b42676873bf34b71b1381b7c11e9450372ce7ce6a07057530"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.12/sp-linux-amd64"
      sha256 "79366521d2b6fb9c298c00a6a64153959a75ade5417824937dcb2255bffa5a09"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
