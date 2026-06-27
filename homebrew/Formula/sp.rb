class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.23"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.23/sp-darwin-arm64"
      sha256 "b24b1a877dda766521e50b6f7cca43436491b6460d6cd17345d72d98c5b1d8fe"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.23/sp-darwin-amd64"
      sha256 "be8ae8366945379a3a0d9ceaced8b0c82249656a9d5f364d27aed38c459d7e1d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.23/sp-linux-arm64"
      sha256 "59bb8eca1ace91d3d9810164579abe353e0bec9518c51cb968a8ad50eac09ed4"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.23/sp-linux-amd64"
      sha256 "51895e3fcf9774cf62c01e058ad6dcdfaa52affe29af7fd2484955e06d09d4be"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
