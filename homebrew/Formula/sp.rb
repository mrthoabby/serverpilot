class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.8"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.8/sp-darwin-arm64"
      sha256 "83403e1394236fdbae781364b3b0977eafb89f5286b77355357994ab5d76a90b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.8/sp-darwin-amd64"
      sha256 "e29c8aeabe8d765bf764a92c69ee1628f012772c15670605534178c3fbe45e4b"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.8/sp-linux-arm64"
      sha256 "af3cf5a0ec85695ff44ec6437355de92a1f79ced66ec4e53fbc829d7bb394313"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.8/sp-linux-amd64"
      sha256 "9f5b50a2378cf9a1533380886da871771aa50ec955cd6dee6d5f682cb55db9f9"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
