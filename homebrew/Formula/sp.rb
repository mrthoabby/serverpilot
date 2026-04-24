class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.1-alpha"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1-alpha/sp-darwin-arm64"
      sha256 "1748eb7c0286ceed70c4c5a97a54acc8649fd7ebca7c139a14b0fb1adb15730c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1-alpha/sp-darwin-amd64"
      sha256 "63377f207a8e15cfcb8b128caa451154f477ca96eb2cd0298ce2613e2666e699"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1-alpha/sp-linux-arm64"
      sha256 "762a11b5671905033e4864b04aecb819f49330997c47c50f372ecbad856f9d87"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1-alpha/sp-linux-amd64"
      sha256 "e8bb120841b444bed8e7402bb11a291b124c9c84fdccf9b249454d3d6ac655bf"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
