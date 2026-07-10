class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-darwin-arm64"
      sha256 "fff886d5ddcc0dc781d462c2118a3325be2a00b8d28ab4e8aca4f90ab6521358"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-darwin-amd64"
      sha256 "b2e8239282921d7a3ff79c73daf45c476ec4f0cc9facaf66fb33d12fe9a5cc80"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-linux-arm64"
      sha256 "d4ef874a7f1422a16d7c57d218771c9ba1ad1ba600aacad987cad1fdc182e319"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-linux-amd64"
      sha256 "9b30da91f47390abca50b4261da6eefa8719928986f857cb40cad39149bd71ec"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
