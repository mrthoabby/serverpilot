class SpAT1.3.1 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1/sp-darwin-arm64"
      sha256 "c41f4c9133d2ff96a79cb0a3d75525799f2b1f8a8cc954bf5f08bde0c5df5a40"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1/sp-darwin-amd64"
      sha256 "24a840a9753757bef399316e1d413e7842170fc1fabcee5d6ad58dcb1c129dbf"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1/sp-linux-arm64"
      sha256 "95319ab631c7091e53a7d95b432981464800344554e72f2b8e574b4ecf466145"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1/sp-linux-amd64"
      sha256 "fad057ca63ecf49f17b5c1b077e54475e4b35a2ccd4e16f545660667701fbf89"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
