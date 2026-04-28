class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.3/sp-darwin-arm64"
      sha256 "afbd15d325e16fc297b5aefa6df287de9772ddd93f927e3b7f3420648a44e15e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.3/sp-darwin-amd64"
      sha256 "59ea749693724e721fe1bd1276c56cafcc51ebe800e5860990c6ad4d9f75bc1f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.3/sp-linux-arm64"
      sha256 "a6291dd9156e890523d973c13eba9897d847b88cee2e055d351ae1cdda3cc224"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.3/sp-linux-amd64"
      sha256 "b8ab105c13f057d7dfdea94b3e5abe322f263c05d95c9a1c20e7c88b8f344dc4"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
