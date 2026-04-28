class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.10"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.10/sp-darwin-arm64"
      sha256 "f7dde3665c24ede25a443b8c70e4f2c2022864f45c2040a3855733a9ce329fe3"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.10/sp-darwin-amd64"
      sha256 "659c169b144d2e0f1289c3692f50e134d826bed63ed0d3cf07ca7f92396d6494"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.10/sp-linux-arm64"
      sha256 "4c0836e32a2c8b50299c292161a1599fae561c7218aef1479d7c86002f2076bb"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.10/sp-linux-amd64"
      sha256 "82b5e32edd44b2a821f1aa0dca72c7a981c0ea6d80d0671aaabfa4addb433761"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
