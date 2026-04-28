class SpAT1.2.2 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.2.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.2/sp-darwin-arm64"
      sha256 "71a2453ea0de5d711c47b4b97dc5a261eaa9977ee4cc2d312a4b9007879b572c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.2/sp-darwin-amd64"
      sha256 "82ddf9a552c8b300e895025db516ca3fbd48bd42d2e574550a4d6f49a33d54da"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.2/sp-linux-arm64"
      sha256 "40fa2dc677c5d9d05ed598baead42d9a4cfc0559af9fe05a1cbafe2f87945b7c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.2/sp-linux-amd64"
      sha256 "bc36b64ab32bfe6dbc2b5a98f7dc3c6a1cdfb6f49a59b61ca4c1b8e05b1ac60b"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
