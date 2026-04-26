class SpAT1.10.0 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.10.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.0/sp-darwin-arm64"
      sha256 "b9b5b6f7bc9228a9a0cd0c537496f1cfb3ab75a199b7e5fa8f906303d1d2f43b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.0/sp-darwin-amd64"
      sha256 "af4152c3f24b11f067f15467158d3bb26a7c719bee12e4d54134ae23041e4b3a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.0/sp-linux-arm64"
      sha256 "6b225693af44a06845797b53bb5c6f2020224ee5c228ce01ebcabe5351dfd9fd"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.0/sp-linux-amd64"
      sha256 "47fdfcc35b5675a834e9fee7889f55b9f8bc68246859501889ad47116b5d8875"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
