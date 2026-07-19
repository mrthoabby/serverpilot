class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.4.7"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.7/sp-darwin-arm64"
      sha256 "7cf86ea2da368c16cba4850df2b62f34fef500a2a351227f8be191f1f622dc8a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.7/sp-darwin-amd64"
      sha256 "acbc5be1b194b3627ff0eb5779d539506e92d626b0453c92a9ae7903a35f3d8d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.7/sp-linux-arm64"
      sha256 "b1a930a1dad7b697aa4c2ef8e3847fd7d4cde3b1b5a3fb735f8d24dd57a5fd3e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.7/sp-linux-amd64"
      sha256 "56f1ac158bc142ae69018c72e3cddd1987b21c6b08e8a02c953b27e7021a7561"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
