class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.4.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.5/sp-darwin-arm64"
      sha256 "eb43ade17553d6b2a27913dd3989228fdfdd118d8191e7c14cc98b01f9cf19f3"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.5/sp-darwin-amd64"
      sha256 "73c3f8ea14ff62d25d562f0790d023c6fc4a76d3590506c6db3f2a7e5df8789c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.5/sp-linux-arm64"
      sha256 "de37b40bcabbcdf32ae432cb452ced290b64b4655ba6ed72de7980a50f5c678d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.5/sp-linux-amd64"
      sha256 "2e9bec95ca00db3efe29bbfeea57b3b0e9c4b20363209190a0ba571db91c2437"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
