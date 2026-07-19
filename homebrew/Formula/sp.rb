class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.0/sp-darwin-arm64"
      sha256 "3a10d7c198c179330c589d4b0dea65c0013c79314c8908acca95e7e0a6d52052"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.0/sp-darwin-amd64"
      sha256 "6d49682887fac606684a4b42df57aed5bb2a824c7e4ec6b1bf75ca380f1d5f92"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.0/sp-linux-arm64"
      sha256 "1f123ba46fdb49fe6e162eabb5c08176792743a1cbfcca4ac032b1a6349dcb81"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.0/sp-linux-amd64"
      sha256 "bb294c421477840874a895cdb58b244865b6d48b83533179ea266f7945ae98f7"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
