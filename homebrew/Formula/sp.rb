class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.22"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.22/sp-darwin-arm64"
      sha256 "6f4f1722916908a0886deb97ae9e9a354deda0438aa9711b11c6b256fe4892e1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.22/sp-darwin-amd64"
      sha256 "83b7bd7f1b7d31b583b16669d6b936f6430ce826ee6e703f1271b1ba29fc1c17"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.22/sp-linux-arm64"
      sha256 "b271051fb566734b4ad315f14ca9dbe9e83bc8c8f6111c2a718eca5bc4dc4358"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.22/sp-linux-amd64"
      sha256 "ee89b75c0df9efa81bee37aa6421c50a852dd92745511cc8dbfaf52b3a1ac3a6"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
