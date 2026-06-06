class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.6"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.6/sp-darwin-arm64"
      sha256 "630e0744b776032ca92632c78f29fe9e30b7bc185dd9197d1054fc82fd217ee0"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.6/sp-darwin-amd64"
      sha256 "1efe2d2ca7fcd6ff489be85f330420d5da0ac2ac994a188c3da3aa2e64fae4bc"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.6/sp-linux-arm64"
      sha256 "4077c7529840a9e73b0df86526c7e38d955f4f39f961dd6b8b2f86dd54a106ba"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.6/sp-linux-amd64"
      sha256 "e84683d04c69ec871bb056ed8d539fe5894d86be3ee830b36d89ce73b592c749"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
