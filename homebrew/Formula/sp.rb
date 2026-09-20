class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "3.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.0.0/sp-darwin-arm64"
      sha256 "5904c9bf35b4c82c6cf8d82e881fe722c25ac09ef2b163f35805afafdfd42748"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.0.0/sp-darwin-amd64"
      sha256 "c6d96aeba137d978b532966bed0c2ee9455c5fd8a3fe511653ecf0a13f1ad7d5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.0.0/sp-linux-arm64"
      sha256 "c7b68206145b19b3e6f676a8d387ce5a8d569044504deb517a573b6bc188106a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.0.0/sp-linux-amd64"
      sha256 "dbb29ed67c3f7be871dcd8d11abcd9539c1ea9fac6d811af5d5798ae5709549b"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
