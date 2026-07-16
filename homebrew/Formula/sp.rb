class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.0.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.2/sp-darwin-arm64"
      sha256 "900bea8d73002ded37738b2da08c23b44fa14d12f177d6316ab32449d099788d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.2/sp-darwin-amd64"
      sha256 "a9e0deea63af93b1595c90eb1ecf09d2915b6c0cfd1097647eea61ab7ff32819"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.2/sp-linux-arm64"
      sha256 "6bfe4844419e8607315933aa1f81e2259b1b6e281510602c9df7ab6d9bbae850"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.2/sp-linux-amd64"
      sha256 "a788f78e93f8e55dbfc61741d5d15e7f057cb386e0998823493b54f979e1531a"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
