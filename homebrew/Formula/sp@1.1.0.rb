class SpAT1.1.0 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-darwin-arm64"
      sha256 "29a43501e706af644274aec8bb4cb359f92db658a8ac77afa0bc9e7ef1397938"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-darwin-amd64"
      sha256 "16fa22cb30195830ba9ca09ed88424996ae55df08bb9e7a7d4bf2628c9e3a602"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-linux-arm64"
      sha256 "204eb297435a755cd9b936cbf572c86967e05c44c66cc2eb791c557b813c3973"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-linux-amd64"
      sha256 "41b1a8409c634d32da75d869eba4dc6f36a89e22db8031ad409bb99b58621af3"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
