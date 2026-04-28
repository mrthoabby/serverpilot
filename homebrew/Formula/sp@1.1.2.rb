class SpAT1.1.2 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.2/sp-darwin-arm64"
      sha256 "223304d89d87ef66f9d73df4b9ab473c582c7417b73a11122b3b2e4e1321a4b5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.2/sp-darwin-amd64"
      sha256 "25f2b45fbd055a54fa0d25a71398da103f48c453c76540517a0ef4e9ea4dc9a7"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.2/sp-linux-arm64"
      sha256 "2afc6f9ea250642924d9123a824ab0bb614d44beea1f6eaa16850bab3cbeac82"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.2/sp-linux-amd64"
      sha256 "347bc9c37ce1f3d30e194e390d9256a2b954cad2efb06af7bda2d89482e9ae67"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
