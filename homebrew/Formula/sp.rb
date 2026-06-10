class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.11"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.11/sp-darwin-arm64"
      sha256 "c9665ba78645d3ed743bebb94d66f6b34383e53156e64fe4ea2b671b1bdedaab"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.11/sp-darwin-amd64"
      sha256 "efff75b96d518607395fe7107bd2478abe3b6d848b726dba71bad5c789cfd636"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.11/sp-linux-arm64"
      sha256 "b9ccceb2487bb7789b59ffe1dd365e6086155363572802579e50f69fb6b0f029"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.11/sp-linux-amd64"
      sha256 "5661195446a817fd0fa908ddce2e32ccc33d39aa5a930cc70f0f911cf27ff71a"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
