class SpAT1.4.0 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.4.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.4.0/sp-darwin-arm64"
      sha256 "b40f2e6357304a14fbdc7ab38d6800dbba21bd3b28d47bbaccc689b58e7a78cc"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.4.0/sp-darwin-amd64"
      sha256 "31f0bbc7209921912a8aba56f209b02ba0e134a14a422496674c551584b18129"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.4.0/sp-linux-arm64"
      sha256 "94016a8e5b8c1081b82f43f185848f2e8cf29449237487450118c99ae3fdd253"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.4.0/sp-linux-amd64"
      sha256 "4d168d12dc1339ecfda7f746fc834e73296d1669ef0164a2215878930a536b5d"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
