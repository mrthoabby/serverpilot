class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.3/sp-darwin-arm64"
      sha256 "851f84e7451ae4e0199d5da65a779e2f6830e5005463529bbfc4a0bada48a92b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.3/sp-darwin-amd64"
      sha256 "d175fb1972c920ce85de25026fe6e832f2dab9393f89cabed1e1cf54a11c3cce"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.3/sp-linux-arm64"
      sha256 "10a305362ace0d38e96163ce64336a060e758fd180a4738d4a0de28663da2da2"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.3/sp-linux-amd64"
      sha256 "96a3edfaec66310dab57f42d40035c9873525b071065933b4fb124f8dc3465ad"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
