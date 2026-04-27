class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.12.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.0/sp-darwin-arm64"
      sha256 "1da4842a8329523289905fe92514b7e8a6b955db5d019b90b6b82005ac091be5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.0/sp-darwin-amd64"
      sha256 "2ecd263aa6787c57425d00deafedcb951c260e57a5e9c8778bae942c487b74dd"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.0/sp-linux-arm64"
      sha256 "091fee836b49dc11272145a2150d2375534f3ec7e8994cc1b40a32a37f6c9cc4"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.0/sp-linux-amd64"
      sha256 "fc7ea21355c5af86993ed2453a3c97a72e8d2190ae055844ac2c2954ec4eb195"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
