class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.11.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.1/sp-darwin-arm64"
      sha256 "1bdbfa98c0183a04357dcffba043d8b13fb8bc6d10466d4fd080616e8dc42b0c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.1/sp-darwin-amd64"
      sha256 "740c794675e11075fc08726b23aeae9efa3c53f142d77cab1d1b5e531b6f4860"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.1/sp-linux-arm64"
      sha256 "fb98916eac106acaaf8dab49798ce7423431d764362e96f36ae064d8d57c6524"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.1/sp-linux-amd64"
      sha256 "71dcf654bac2dcd936dd7d53212504f452b3ffa49b0be0dbd3be55321a74f520"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
