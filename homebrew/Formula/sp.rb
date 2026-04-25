class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0/sp-darwin-arm64"
      sha256 "44fafc78ea0f5c5b20c0f16f02356a35864a9fe2b662b37ec08bbf48ea9026f9"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0/sp-darwin-amd64"
      sha256 "9123e4d8784eca6ba30bad458fa5a92549797b50316af11e83985050785972af"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0/sp-linux-arm64"
      sha256 "483c8daa2cb1d89c4cf1e295b9f91a9859cb3e23829497349cbacca37ebdaaf1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.0/sp-linux-amd64"
      sha256 "2d3c254188a1e06b85e7dab52f470b9b508d2953d98d25f6082835928545c2c0"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
