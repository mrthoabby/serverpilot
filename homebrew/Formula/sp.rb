class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.25"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.25/sp-darwin-arm64"
      sha256 "6da59d4d020c897d72f8d4a76ae364e5e6f6dd8b5260f52b91785a2ae233d033"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.25/sp-darwin-amd64"
      sha256 "37294d541057b0c3bc4401547c04783fa7fae91e35bbe07c22915528919e806f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.25/sp-linux-arm64"
      sha256 "e7b03a7a34ac59f6f25ef84413e4c68663fa97c50fef0651aba12da388a9f53f"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.25/sp-linux-amd64"
      sha256 "95d6383295cf16667369c86f01cd8f6942f51a5b1dfee3f1bea651a9741fba96"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
