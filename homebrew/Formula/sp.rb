class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.5.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.4/sp-darwin-arm64"
      sha256 "322215876585900f8a40e7bdc88d8e34899caee6463fa6c503d0cdc891064bd8"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.4/sp-darwin-amd64"
      sha256 "dafb59df31c489cef1c7a0cc0f0a490142772a429c94eac70b82b5d65329c8e3"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.4/sp-linux-arm64"
      sha256 "7e142803f4d85a8821ffa85941e56c3876720e3542acc0e203690223ea3e7653"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.4/sp-linux-amd64"
      sha256 "a7a5fc5abb84ea94b9f778b6acd57c7ad0955e73218cad65aab54559d13e0a90"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
