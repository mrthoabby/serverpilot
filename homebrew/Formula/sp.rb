class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.12.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.2/sp-darwin-arm64"
      sha256 "fa64fe83a82a4bc6583c932890a9a53a90d735f5abce743fdc6b4f9128aa53ba"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.2/sp-darwin-amd64"
      sha256 "c517b8a08fccd43a2379294ccd0399a6930090fdbb80529e44d4fc96941f2ee0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.2/sp-linux-arm64"
      sha256 "5881f716eaa9a466485b3b70566c96e0b3308ab7820b2a1d0de082eb21ad1a3e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.2/sp-linux-amd64"
      sha256 "d38f9ff2752a2b1d5b4e3f70528769de975d6e4775f3e021612023febdd18a5a"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
