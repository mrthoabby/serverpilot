class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.3.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.3.0/sp-darwin-arm64"
      sha256 "5193e5aabfd8fded27fa9216504d66f3ec1ebd377d16ce1f5e2d7b11d066d80c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.3.0/sp-darwin-amd64"
      sha256 "5e23f6bdc7107f1c9d006b533b18488bad84d9384efbd73e8421285aa074ec3c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.3.0/sp-linux-arm64"
      sha256 "203eb69f44aad88e4901aa8c5fbf69929c81b135761b30ac66bb4f9933c0dd9b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.3.0/sp-linux-amd64"
      sha256 "274aca0554d0da45d2d1e86eb9db2432e78d6cefbab9d4498910690a805038b5"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
