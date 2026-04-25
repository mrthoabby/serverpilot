class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.6.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-darwin-arm64"
      sha256 "99b550a5193f9fd18bb8f7fd510856e93e0c471abed8393b1a499f486a98bdf4"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-darwin-amd64"
      sha256 "99132de489d3742d67dbf4c9cc28cbe354cb87e8aab23dac2861b6b1f8485f78"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-linux-arm64"
      sha256 "945843e22e76026f45e7eb8ea70e9e69e0b6b2b4d04981326d9972484257aaa2"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.6.0/sp-linux-amd64"
      sha256 "56942bec3f8edaa65f49097a03d05a4a7d1ba1791031c8d3d8494152c7de5999"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
