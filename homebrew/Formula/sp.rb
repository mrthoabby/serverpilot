class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.5.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.5/sp-darwin-arm64"
      sha256 "0cb99e9c8ae969491994529479c67fed06f75ba89da6710d6e7427d0a0fce713"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.5/sp-darwin-amd64"
      sha256 "b48ecd3ca7f274e855d4677498ab5a7f5ae64574d3014e95a74b79cdfcbc8909"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.5/sp-linux-arm64"
      sha256 "46e8dceb4d1a9bbbbe8d07de6946dcf73f08425f1ded259f622d6b006fe9f922"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.5/sp-linux-amd64"
      sha256 "d735874a6136191b5542b65aa6d9d5705aa22137df0baae79d126884366baa8b"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
