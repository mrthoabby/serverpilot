class SpAT1.3.1-alpha < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.1-alpha"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1-alpha/sp-darwin-arm64"
      sha256 "cd7cfa2b08e93076db054e49ea1ba2727e4c53ccdc54e20c7ec10437e227b4cb"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1-alpha/sp-darwin-amd64"
      sha256 "8584f6571be2a0df16dc6f789d0dad47b3a881a9eafb1666212f2f1cc42bd8aa"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1-alpha/sp-linux-arm64"
      sha256 "a2b89dd89fcd9ef2bf6cc0f179b96e08254222397a0c00536caa970c1ae87471"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.1-alpha/sp-linux-amd64"
      sha256 "ddefedcb95086c3529dc522d0b8fcf8d5cb09760927bfd233df794f5907dc9c0"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
