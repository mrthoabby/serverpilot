class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.21"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.21/sp-darwin-arm64"
      sha256 "14c83fc463280be684878e7bb504caf790a7dab9988825aeeffc823d2c3e52c1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.21/sp-darwin-amd64"
      sha256 "4428ccb76268ca33a860f83e30756d8f7bbc782c2e125889bc55bd4731aa53fe"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.21/sp-linux-arm64"
      sha256 "19790b5a3f287c4cae65fa8aeec126c3133c67d6de2371d189ef5272d441c9b1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.21/sp-linux-amd64"
      sha256 "6a13d6fcd2734d2c84cc63796a2a83c755ea74cd82327a9c98e08d98b1c847e4"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
