class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-darwin-arm64"
      sha256 "f3d9e883085e71693d4a933c7ecf0328dacc961757c39416a1448f3ed60caa26"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-darwin-amd64"
      sha256 "a9b748a4c347a8d72fb3f5750832d36979dc9e95711d310003fb69f0ba87e2da"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-linux-arm64"
      sha256 "11ea8b51fd7c3836deea3953e687c5ab41cd3a124cab95df82dbe293d5fe1ea2"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-linux-amd64"
      sha256 "03462b8e3468894619fdae3a647ebe167943180afba20bf522c15591a905d46d"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
