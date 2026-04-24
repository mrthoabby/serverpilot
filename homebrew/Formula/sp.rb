class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.2.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/mrthoabby/serverpilot/releases/download/v2.2.1/sp-darwin-arm64"
      sha256 "a9c3a3fef961796b102abe9b6ad5861e9701913ceb7ccfad802b30818f5dce74"
    else
      url "https://github.com/mrthoabby/serverpilot/releases/download/v2.2.1/sp-darwin-amd64"
      sha256 "0e5aeaaf8e487fe95e842101a9d1139261c6ff9f0f015d354eae69018f3d4f3a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/mrthoabby/serverpilot/releases/download/v2.2.1/sp-linux-arm64"
      sha256 "2303e30eddb288be47953c5e6e91527ffcca28d4d8857e84a52df29f8236e16f"
    else
      url "https://github.com/mrthoabby/serverpilot/releases/download/v2.2.1/sp-linux-amd64"
      sha256 "23322c8fdd2f599c2a95aa4d12e1ffeb9637c7442dd06b70679d897f3da61549"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
