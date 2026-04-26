class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.10.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.1/sp-darwin-arm64"
      sha256 "5be1ec00e05aa5e0a5b73fa32697424b4406120b25fbdf4a9a0575f5460aeb10"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.1/sp-darwin-amd64"
      sha256 "34c9eaf8d25d55f73e2201879321903840aa812ce7844d7e7fa8592e699b411c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.1/sp-linux-arm64"
      sha256 "c0b6b903c7c6aead7bab825975af41c88515f72f0be70181f2174e829322e47d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.1/sp-linux-amd64"
      sha256 "2ceaeceef2be29a0a3f60c330bce3ad347dddb3f28fc786c8d7a65d020af6763"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
