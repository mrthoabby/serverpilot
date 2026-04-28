class SpAT1.2.5 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.2.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.5/sp-darwin-arm64"
      sha256 "b18d8053d68a5d5a449240b82f812c5e31c2339504d51cedb8bb008a6302d448"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.5/sp-darwin-amd64"
      sha256 "900297fa3c9c8f46778ed31f514751fe38d6c164a09708d7fa32d5e5e0ecc0b0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.5/sp-linux-arm64"
      sha256 "34e919247df44198b59818044d2f306ded1b1c245c9899033371413b7a583218"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.5/sp-linux-amd64"
      sha256 "1e514c731575376848113c2ec8870b16a5c3d2450a860242f46a57babeaade19"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
