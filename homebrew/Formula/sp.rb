class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-darwin-arm64"
      sha256 "d933f3634277f20a0bd91648ab89460233ec5965039d441088b24ff44387813e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-darwin-amd64"
      sha256 "af5813fcedb442637eac0928f6050449239506a64c00e2ad5a5555cba18f57e4"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-linux-arm64"
      sha256 "7fb75b5660e6bc0fee8a72bc7dfd14c37953aecffe4b80844f0a864d1a615c4a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-linux-amd64"
      sha256 "820a7307e6ac2f8d84311ac0006f71c834ba699f03fd1ed884c63a3c57de9231"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
