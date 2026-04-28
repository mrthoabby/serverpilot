class SpAT1.3.4 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.4/sp-darwin-arm64"
      sha256 "cdf6729f31bbd4b6354d1d3101f8a9fa9a39909e266cf47fc7dcf003987b9823"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.4/sp-darwin-amd64"
      sha256 "8522a05568ef017b98d41d984a64fc5a2c8f6ff708911108dfbf00348104f2b6"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.4/sp-linux-arm64"
      sha256 "4ef985be773bb198b1da5b5718ec1a46577f366bad9fb23bd99440336e6396f5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.4/sp-linux-amd64"
      sha256 "71f0a2c5ae18d30e9fa646829f8656e4cbe1b68552745697639dcfc204032eb7"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
