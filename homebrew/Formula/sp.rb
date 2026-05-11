class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.1/sp-darwin-arm64"
      sha256 "c745cd8d80e79a04aea1e04848fc43c7797d53165a3726b4c61873d6b2789c15"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.1/sp-darwin-amd64"
      sha256 "2a937a92ac8eace742b91b5dccf226e54fc90bc0fabde88379ed9f954e6b6c21"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.1/sp-linux-arm64"
      sha256 "604cf15a3d85a162138c16ec942d770a5577f91fc1204900f2f2212cd8081b69"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.1/sp-linux-amd64"
      sha256 "ac19da8c001a228abb6c01b8e5f91b4fe9e47557660d9e35eab931d8c515af02"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
