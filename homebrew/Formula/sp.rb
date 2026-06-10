class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.12"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.12/sp-darwin-arm64"
      sha256 "ef28b6ddee78b90083230096104929385725a183e2c3b1f7316bfed31bf69027"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.12/sp-darwin-amd64"
      sha256 "04cb40d614cc74d9536895975c642049e67b14a1d221d0a1ef14b612336ea3e3"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.12/sp-linux-arm64"
      sha256 "e41eb72324298d41f798906e64b1c29d2106df9fb126db5fd7af440db8f68ae1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.12/sp-linux-amd64"
      sha256 "391d8c81bbfb2789dcc38a7101d10a158b877a3e18277d1c5ec62ffcb057b7e8"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
