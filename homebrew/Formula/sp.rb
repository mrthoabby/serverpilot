class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.4.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.3/sp-darwin-arm64"
      sha256 "1670a8ea162b6f26f0a7d326e271ff1b9995a6e7b91c7c7951fa1e3beabe260b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.3/sp-darwin-amd64"
      sha256 "a7bd7027ff24637d1d7ab9c999f930c008a6785052d1a8c5060c5e2a71a4649b"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.3/sp-linux-arm64"
      sha256 "18262a36861afc552010ba4e10a282018ef1637c477b0ece69a64d62dcab2479"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.3/sp-linux-amd64"
      sha256 "293285248b2469ec348da955b343ba1a04d6d73fd0023707f2863d410b660bf7"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
