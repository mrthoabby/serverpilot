class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.3/sp-darwin-arm64"
      sha256 "6f74f647e42f055c00f227439602a1a925dcf57d1082c28a4c50813872eb7fae"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.3/sp-darwin-amd64"
      sha256 "6d347905c4df7ad4ed36eeab63334e7a780e068de352a2c8e6b7f0fda90174ed"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.3/sp-linux-arm64"
      sha256 "d499c59ced401587e8ddddddea2f8eadc2d650fed4c25fa920b35a477c04b71e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.3/sp-linux-amd64"
      sha256 "83e251985d9c2bb6ff4e76e4746683d6fd57b36211ec9f1fe29dd22da02ff789"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
