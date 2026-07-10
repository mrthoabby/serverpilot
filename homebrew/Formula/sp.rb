class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.5/sp-darwin-arm64"
      sha256 "329dd618fe1dcb909625c1e79a8791f0ab2ee1d1af3953161f22693dbe363ff9"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.5/sp-darwin-amd64"
      sha256 "2f5a7ce3d1042631a7d5d6e7bbed92638b74026750ddc9b0202b0c0c7b757740"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.5/sp-linux-arm64"
      sha256 "7d0f3ed578e793629e49d20b8a106ea16aa9e3c9145de2198030d21360edd5ae"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.5/sp-linux-amd64"
      sha256 "8c4a3d23faf7cf5ca6c31cfa2cf88acbd00733ad07cca319aa6984056736579a"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
