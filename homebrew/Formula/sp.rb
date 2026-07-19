class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.4.6"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.6/sp-darwin-arm64"
      sha256 "43406c7d3da777377af2352463413b2b95459b70ed5264cef19a079daf0ab06d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.6/sp-darwin-amd64"
      sha256 "e032879f95021fe9b2eb4f743ffcc9d7553d8f2c91e48adaa6694ca99fb7dbe3"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.6/sp-linux-arm64"
      sha256 "f2a99e73714af02eac346eecb2f8a593c3f414335ce36d66f0bd3944145f5511"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.6/sp-linux-amd64"
      sha256 "4d1bae105c7334bf15ebc7001d85bb2422f9e13447959d8172984161cab5264a"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
