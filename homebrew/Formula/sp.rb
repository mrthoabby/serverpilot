class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.19"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.19/sp-darwin-arm64"
      sha256 "722e1b9ccdcb5be6553f5408f5d7cdfd79ccb25ca07fe4986893cbce5d0c1034"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.19/sp-darwin-amd64"
      sha256 "c9ca5a4d34fae0247536a163caf908b35f5ebf1317eac0ddb7a49095a1d947d7"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.19/sp-linux-arm64"
      sha256 "5293b84c35af1279322859a1f64cd2f8fcf9eb13649cb3c6045d38bc294d3b2d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.19/sp-linux-amd64"
      sha256 "da9e2275d8945a85c9dac4fb9fe74e620de0d1d0ef6f14c7fa296f595b13f92f"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
