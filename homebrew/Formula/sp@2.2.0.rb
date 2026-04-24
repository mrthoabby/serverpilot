class SpAT2.2.0 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mrthoabby/serverpilot/releases/download/v2.2.0/sp-darwin-arm64"
      sha256 "35604b7211d34d3806703f039ca33aa0c73051f661b739be84ea927accf06f01"
    else
      url "https://github.com/mrthoabby/serverpilot/releases/download/v2.2.0/sp-darwin-amd64"
      sha256 "b4279f8b3cc611dcfde0875906e49f970b774b141761d18b8962b91efb035ca6"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/mrthoabby/serverpilot/releases/download/v2.2.0/sp-linux-arm64"
      sha256 "693ab74161399819a1826cf030693b8a462a2aad3a3a82e4abcf572dbd418314"
    else
      url "https://github.com/mrthoabby/serverpilot/releases/download/v2.2.0/sp-linux-amd64"
      sha256 "d0416b75b610d265b4781b31ece3879cf51b893cb19b93f6f8b048f4c9081a05"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
