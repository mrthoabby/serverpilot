class SpAT1.0.2 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.2/sp-darwin-arm64"
      sha256 "0749ebbb9d2ee3cdbcc9f66ea0ef63e76843452d3aa6b9c77b9ad1f06eda5426"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.2/sp-darwin-amd64"
      sha256 "a44bd657dd5abf50d0751a0119f3440232ccbb38d689b60e4d94566b1c5c0f14"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.2/sp-linux-arm64"
      sha256 "1fa29ab89ee68b2949385258e47d367e9c0b8594c01035399c458787f44a83d6"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.2/sp-linux-amd64"
      sha256 "aa0b8554125f1ff118d537b1678c6aa2ec10e331dd6f46cb5d535e6f1b7571c8"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
