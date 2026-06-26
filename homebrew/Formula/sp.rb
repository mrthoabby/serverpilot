class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.16"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.16/sp-darwin-arm64"
      sha256 "436c099bf79c4ab854fd3d4b6fa1ca4eee5e52f8e034b073c60fb7f5c447c1fc"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.16/sp-darwin-amd64"
      sha256 "eaf2a464cc5404e3cd0123c079d562c450d882c74e470ee999828c2c2de34105"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.16/sp-linux-arm64"
      sha256 "0eec8b504e8f546c1da17f3f42efc5414dc07317ac73a55f6b0289b705d357f0"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.16/sp-linux-amd64"
      sha256 "74b03bad75bca8c14ba8d1ecfb0f58b471f8b2d25ba2e97bcb648804321eda3d"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
