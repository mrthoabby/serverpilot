class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.10"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.10/sp-darwin-arm64"
      sha256 "3d036bff84fb5fd83f028c60c7e854c0ccabee308737a87967a3568fa006731f"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.10/sp-darwin-amd64"
      sha256 "9ee5796550f31c939b16b8fdc6be2e7518c421acd9f88c9f7cf011c57b675062"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.10/sp-linux-arm64"
      sha256 "04f3bc4c29fb27638838264f058e19cb81367a3d2f1923488dc69fc01fc17973"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.10/sp-linux-amd64"
      sha256 "65729b8340f4f707ae978cb1edfe76e2e7e4837459b2599f2d1ce46a387f7e71"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
