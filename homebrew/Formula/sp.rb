class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1/sp-darwin-arm64"
      sha256 "999621e2eb3ed61c5b9e765316d5b170bb3891762a73128a7c72d7beb2a9e5a8"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1/sp-darwin-amd64"
      sha256 "0458ff05cceed0c5a18fa1216142b124f66074a91dba3a3793236e828af4240a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1/sp-linux-arm64"
      sha256 "0dc26e7e4924c101f1dedf9591afa3cdec655fdd12e7b10f802080c9f0361c01"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.1/sp-linux-amd64"
      sha256 "eb33c36e1850bd545b1c386f4b5005050e06989c4e1375cdfe86e7c9c79d0a1e"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
