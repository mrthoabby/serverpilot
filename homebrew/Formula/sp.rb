class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.9"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.9/sp-darwin-arm64"
      sha256 "adbe43aacdb7c99efc90aa2bc45f2b2b929b213bb27cf677cccbf424330eadbf"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.9/sp-darwin-amd64"
      sha256 "ce3046060f9ec2dad90bba511cc0b680c0deb3ab0f9339ee44b4b0bc9b191577"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.9/sp-linux-arm64"
      sha256 "e4c64df58f0e3d36f8c3ac183467760a84aefd3ee326a1624210b849fe312eef"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.9/sp-linux-amd64"
      sha256 "e1d5143d63a1a59e24c70103874e6a4fe2c6ecb8aa6d2f02f381a92275707aa0"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
