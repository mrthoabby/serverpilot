class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-darwin-arm64"
      sha256 "ce49ba2e39436cc8e876b67706bc1ee77f685565e1ad5eebecfe1b42dce60fac"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-darwin-amd64"
      sha256 "10b1bff0ae54b64cf91313a76aaa01650021ee60bc694e867adb941a168a3fec"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-linux-arm64"
      sha256 "a8ef539f8e9aa59ad6fa6ce2eda2a6a5cffad0991019d1a90dec5473370d94a5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-linux-amd64"
      sha256 "1c3b9cc1b4247e44b1bd88dcda598c76939809169f348071359ea017ac9ab858"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
