class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.8"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.8/sp-darwin-arm64"
      sha256 "ccb71781d68260d1827415e0bc19734ca23ee1acd7d3775cd477e207d5fcbd39"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.8/sp-darwin-amd64"
      sha256 "1ba2948a8179e3d577de8fbe1e010076fa875e58698bd407e9c3b2c8ebff89e4"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.8/sp-linux-arm64"
      sha256 "122bcdef05b03341ce51cde3ce4483a7a925b51a33db39e3259a9f4a21e2cfd5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.8/sp-linux-amd64"
      sha256 "bb03fc5e460a865f21079df473fe88ac6f71bc225ed126cfa2626e40f12d5daa"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
