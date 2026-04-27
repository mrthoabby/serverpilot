class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.11.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.4/sp-darwin-arm64"
      sha256 "146dfb169deb05d35f3bb0b77dca282f856953e9b6b6d5afef0bf8d430eeda15"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.4/sp-darwin-amd64"
      sha256 "2df4893ffe0929ad971c3064a5125b3bc124a57507bd61a17a08126c7caea9ef"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.4/sp-linux-arm64"
      sha256 "b66c88468274b02ad36c62a8fa25ec29f9ac696823f00a57e9c7f31689cc4230"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.4/sp-linux-amd64"
      sha256 "046f26bd9cf97e3b7a5c7fcf77c972a40f81aba09aa14fbc7df7b535c537806a"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
