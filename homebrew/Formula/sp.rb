class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.10"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.10/sp-darwin-arm64"
      sha256 "cd04bf525be0f9b97403e558559a7f80a2bcb83990f3d19638d39623cc9f402d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.10/sp-darwin-amd64"
      sha256 "8a0ace4d321f7399a6cd5698a97829cd6493fe2a94479be1819bbcf5915c3322"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.10/sp-linux-arm64"
      sha256 "6b0bb8c9b64dddafd9a0f953659c2ee4247f782a7128bf389f4ef7623ec755ed"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.10/sp-linux-amd64"
      sha256 "c7f4e0bf1fffa72c3485e02273e186e4c60d6019676952ca0ac1e6c32104d069"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
