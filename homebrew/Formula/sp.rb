class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-darwin-arm64"
      sha256 "cfa9ea6d645f58fdb7faaf04c969a6d970f71b1955fbd85b51d1511afbf66f18"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-darwin-amd64"
      sha256 "6adbc58a5e18b4d99680ba1047ae33a363d8f92409d8790df1d5cd8421594c03"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-linux-arm64"
      sha256 "6d51c182d307713ccdbf1916ab5aca2c514d910235f9accf24466112f2aec09e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-linux-amd64"
      sha256 "bc720188a1681c3261e7608528714f286283e3b424fc59d1a5c924ac39f0049e"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
