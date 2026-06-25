class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.7.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.1/sp-darwin-arm64"
      sha256 "e06b05de868c3302dfc0106ddd11bc89eb21c18abb4ad36c573bd22afa371ce6"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.1/sp-darwin-amd64"
      sha256 "8011844cd7e2cb59a697555b6b869aba6cb1c17d98ab3931406f1d69597589fb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.1/sp-linux-arm64"
      sha256 "9f8a22ea593ed30a8e336eec3755ba5745f03e2bf53b0fade64e4a1fb8521f6b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.1/sp-linux-amd64"
      sha256 "30cea04aea83e675b440afa369c25e1cfadcac7dc349c43de43767ce30df5cbe"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
