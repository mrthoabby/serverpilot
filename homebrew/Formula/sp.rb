class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.10"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.10/sp-darwin-arm64"
      sha256 "defe2a7fba4ba50f5bd655aff8020c2bf5322d36e7512c5ab3653b9a3d9fdf09"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.10/sp-darwin-amd64"
      sha256 "a02b7d2f2921cd001a9653f9185ae01dd5bab857da983e7f68ee0dbf4f8209f5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.10/sp-linux-arm64"
      sha256 "07d46d4cfdeea476b0d5e30b3c92cbaac553f8a63833253c5a160f8d05e5d97c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.10/sp-linux-amd64"
      sha256 "a4e1842ac82f61a42c0f05a6e8e7219f907628d676dab4af602565ff71bf7624"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
