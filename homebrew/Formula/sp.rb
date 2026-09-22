class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "3.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.2.0/sp-darwin-arm64"
      sha256 "a8e5102976575d9c9550dab1c905c16a9d5ff5e53fd211c6cfa016ad617150c9"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.2.0/sp-darwin-amd64"
      sha256 "0272f832e420791a025a78f80c35f4d096dd6876ea7d70da147621a662e34346"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.2.0/sp-linux-arm64"
      sha256 "a1592598261c20e8a47d2f6155113da25c392c0083f7022dffd622eaddea8b51"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.2.0/sp-linux-amd64"
      sha256 "41da9b21ea5f52444f230eed6d9911b15fa0e460cbba502888d89209e949ff81"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
