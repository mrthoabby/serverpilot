class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-darwin-arm64"
      sha256 "069dc96fb1c1dbd65f10c074657003188d169b40ebf6c53554c611b00633109c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-darwin-amd64"
      sha256 "6df7e97023c67f903242ca075a2f7a4db44826ecd8e3c55a51c1128a69fe443e"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-linux-arm64"
      sha256 "7c39dd36ccd38015a6bb7fa792166b4d86e7ee8f2305f8faf8042022c53ee166"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-linux-amd64"
      sha256 "a8c87a95d783cab10b9f60bbd91c1b63bad68f7a758ce360fd71accd1c717e0e"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
