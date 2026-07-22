class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.9.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.3/sp-darwin-arm64"
      sha256 "fa4309baffa7d600161bd514fa3d8bc85022c8e72b296d5118bad84b8a2b4c5d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.3/sp-darwin-amd64"
      sha256 "fcdd39b68ba3bd1a76c648e0f2bded3199d30d98728f45fa7dda9909177edf54"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.3/sp-linux-arm64"
      sha256 "d17478758ca28cf815d985c16d973b401324f4080b6c5f17adb481e791fcf69e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.3/sp-linux-amd64"
      sha256 "a262a561be89493d901c6653849f20cfcc9e512311a681d73a37c4b169d469d5"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
