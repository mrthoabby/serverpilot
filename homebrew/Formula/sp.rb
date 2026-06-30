class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.26"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.26/sp-darwin-arm64"
      sha256 "366e939ecc57efc03d480d0010dab1eb20bf2f2afe1168083aba8b04fbc0a4e3"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.26/sp-darwin-amd64"
      sha256 "e101181dfab13f479ae556000038119512a01efbdd5c27307854870c251563db"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.26/sp-linux-arm64"
      sha256 "5653399fa38c97cde1023a56155f097e4c6d021cccfaceda5701cb9fe9169124"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.26/sp-linux-amd64"
      sha256 "90d80bdb6f7bd1f780b4790d452cb72f32ed7217c9f05cf7cadb8be10fbe40da"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
