class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "3.3.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.3.0/sp-darwin-arm64"
      sha256 "358b85fdecb697da72ac1187547a314e7aca5192fc8ef6dbae4233ce7f73fda7"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.3.0/sp-darwin-amd64"
      sha256 "6247e63cf808e822f694d200c21f2be1ef8307c48f77a9016de2127c6917a616"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.3.0/sp-linux-arm64"
      sha256 "e102fa17590964fc66611c00e9297e3608c606a672f40902c034ec886f53093c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.3.0/sp-linux-amd64"
      sha256 "13a535a71ad78482cd0e817c0dd6bce94497513b536ed7a9f59bfb1b564ca091"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
