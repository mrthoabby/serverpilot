class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.0.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.5/sp-darwin-arm64"
      sha256 "f35d9937bf9215c7be2d065b26c41f1a07b31aa9c121ebc20be7a34fbc1bcc2b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.5/sp-darwin-amd64"
      sha256 "e14b535950a8bf0fdb20a9ea364517843f8a95a495139a017038177776c44684"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.5/sp-linux-arm64"
      sha256 "2d199ef13ba5ce24fecf24f82573c2018814ed955e62975b12bf56de93138222"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.5/sp-linux-amd64"
      sha256 "ea4fd78458b24c5bff90a0f4c3f109282d6a873ef9b369120cc6beaaa1d81d97"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
