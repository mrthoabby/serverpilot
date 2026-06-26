class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.14"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.14/sp-darwin-arm64"
      sha256 "338c4b285f02705116d2c68ca8b4fdae336e8d2215b32cb7ae3f58a8c0156ec4"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.14/sp-darwin-amd64"
      sha256 "81bfc1feff89416f2c6e41912d62d343f98fffb47a3a5a9ee0fd261b0ffcb2c0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.14/sp-linux-arm64"
      sha256 "640096f2cb2690ed52796168b052e6d6f61abf0a5afeced47c67fa6eb3f8eb48"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.14/sp-linux-amd64"
      sha256 "57bbaaf3c868aa265779c2e452db507fda08513249ca3c95b505481be40daf8e"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
