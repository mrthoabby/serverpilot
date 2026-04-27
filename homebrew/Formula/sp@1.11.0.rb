class SpAT1.11.0 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.11.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.0/sp-darwin-arm64"
      sha256 "160e034de7358f48347dbc90854f65c671beffee0aaadffb373a611503c29e4d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.0/sp-darwin-amd64"
      sha256 "c3a7e51be0908ee60bc2030425bb7348877f17fee491f60d2e48172d32e61a60"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.0/sp-linux-arm64"
      sha256 "a26eec4d99b34cb78fd23cd9b5d476f0ce39dacb06500cb51b0d7e7cba4f18f8"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.0/sp-linux-amd64"
      sha256 "90e4f1f0693a523ae5291f254ce25c8a769211b04f9b140850be1b3f303f170e"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
