class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.4.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.0/sp-darwin-arm64"
      sha256 "f2f0aa19627e75570970b33c322c50bb5d2be2fee3c9926bfb75830bd38f1a26"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.0/sp-darwin-amd64"
      sha256 "2526cb75f34dd973ce2cf2e21350dba61d1a7063b276d041196178dd9996ee57"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.0/sp-linux-arm64"
      sha256 "fcd2e1516952208d4a70609f879e42e7e0088ed56b05fc61d765d9f086f2cf17"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.0/sp-linux-amd64"
      sha256 "66787273863fc796fc652647fbb91f8c9b2ceb674f1fb4694a98bef55ae04672"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
