class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.2/sp-darwin-arm64"
      sha256 "1aecb3f64c7288df48c274365f06a7e329aff919f3795dc8f766e35aaee9f7f5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.2/sp-darwin-amd64"
      sha256 "de1239b2e71aaeb460257897a1a81673c9e7ef4c2ea6289d48f6c02b317c80b0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.2/sp-linux-arm64"
      sha256 "df6dbba2596c99f5eb663a8e1c71faa6db6bb14b92f5e7624e9021599484f608"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.2/sp-linux-amd64"
      sha256 "5d0a2e8c8dacd2e079616803018d0652aebbd17bd0e58ea76891e294e3f5a2bb"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
