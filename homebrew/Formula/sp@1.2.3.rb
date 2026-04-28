class SpAT1.2.3 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.2.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.3/sp-darwin-arm64"
      sha256 "ba0faf2ce6a61bdfc01dd1533a97be8d4cf0af8ba95db2957d4f9a23c9ad1d8c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.3/sp-darwin-amd64"
      sha256 "a7386be717cf20f5a1528c416f3a5679f47de4a70a6baec35fbaea7c332f5ed1"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.3/sp-linux-arm64"
      sha256 "dd73180258978e98f517248f5bf80e8310f6886343cfc068f3e7e98291b56c86"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.3/sp-linux-amd64"
      sha256 "66d80cf770fd43f16a8349be35008bc6ebe0151f4a72071a3660269f263c5fa7"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
