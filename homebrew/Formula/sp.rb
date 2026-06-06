class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.7"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.7/sp-darwin-arm64"
      sha256 "3fb78ca25718dbac0d0d680260f26c72df8dafd65e068cd60448e5978d0dfe53"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.7/sp-darwin-amd64"
      sha256 "66e31e54044be7e3c2a76d404db8e0cab2cccfe07bb7384434caf3722082d898"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.7/sp-linux-arm64"
      sha256 "96a9946e9780c1aeac1560f53705135a1de5c10217b6a8a764d45b412ddba929"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.7/sp-linux-amd64"
      sha256 "4421459adb03d08dff0e4f7b40b087cf4e6fb82da4132e12dbc49846ea22a54b"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
