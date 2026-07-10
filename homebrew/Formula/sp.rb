class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.4/sp-darwin-arm64"
      sha256 "9b9bfd711c464087f069bf7493f53ef7f3bab8d31300061fc6db96d6f71ce08e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.4/sp-darwin-amd64"
      sha256 "cc925f76a24f2768cbd8e8c1d77664a8e4f5a4d17d28234e3d9c3ab05c35d7d6"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.4/sp-linux-arm64"
      sha256 "e0abcfd2b7c5c7c2dced11c23dba907baef851dac21d5d997e930dbac679d2af"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.4/sp-linux-amd64"
      sha256 "88adf7179804fa76e1484bb6659b8f20d1165586870ed5992d47d6dcdd335367"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
