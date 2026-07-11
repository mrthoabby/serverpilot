class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.7"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.7/sp-darwin-arm64"
      sha256 "cefc8fa12c236c97867c910dc7b365ff663914458b1a6b07b6a1acec3be6d3f7"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.7/sp-darwin-amd64"
      sha256 "f77c04212cf563e786ae74f423bcb471e6d708d175a69b6d06cab85d8da91b5a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.7/sp-linux-arm64"
      sha256 "9fbdfcb76046fdcb0e639374f9c15f3327f756533ae3fe4a5dac3f2cf84dc1f7"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.7/sp-linux-amd64"
      sha256 "249fb1cc5feb14dfaf4d3ed004dc84053116a917bc6889b3a7b9efe7c44b0d5c"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
