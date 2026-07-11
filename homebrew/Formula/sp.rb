class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.0/sp-darwin-arm64"
      sha256 "cf102d7c507c0b3814eed4a27e0eb6b45aa975865d5d1adc801d183a930fa97d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.0/sp-darwin-amd64"
      sha256 "d4955f3d898d45fc3c60fb9d575887fa8e1cd49379636d77b83e05d593ce212a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.0/sp-linux-arm64"
      sha256 "ea4bb6de25caf8d05a88616c87af5211f0f05d2f8e75e1136585f1dd5db74981"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.0/sp-linux-amd64"
      sha256 "101db5111fffac2a8cdf5496f0f187c298fdcdcb7066b8daf960c482b3b23b20"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
