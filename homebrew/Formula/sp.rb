class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "3.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.5.0/sp-darwin-arm64"
      sha256 "1391c9f77576889c8a4fec9245dae52c4f395a7c163574acf7ffcf4860e14669"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.5.0/sp-darwin-amd64"
      sha256 "f4f904a9363e67f219f2ecb1c6ca689e2b1802f4441b8af6ed3180ebdeb231fb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.5.0/sp-linux-arm64"
      sha256 "8f913287a1f4cbc2efd71cde65ad943c2aeebbd9aa6ac4f433ce78dc803bc0be"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.5.0/sp-linux-amd64"
      sha256 "0bbf048c4092210ed7e44dce72dfc86d010b3c1cd33b1d11e359b265bc372dfd"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
