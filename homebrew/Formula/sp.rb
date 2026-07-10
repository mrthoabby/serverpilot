class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.2/sp-darwin-arm64"
      sha256 "01048617ab850492ed7a600c77b33587cf50174489d050670468ef164ccb70bc"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.2/sp-darwin-amd64"
      sha256 "9deccbf479feb387663274eaeed586f9809d1210f7d2f86f049c9b88ae3ca9d0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.2/sp-linux-arm64"
      sha256 "3c5d8e100c4841afdbfc691f96021982749d0db861a3b14888c1e5a9c82095a5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.2/sp-linux-amd64"
      sha256 "d45460e3cd63e36171c363fc2bbd0da550f53b5d29146317a957a0a24d8904e4"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
