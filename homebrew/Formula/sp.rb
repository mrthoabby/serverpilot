class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.13"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.13/sp-darwin-arm64"
      sha256 "8c9f2bb3c1af9bdbcb8919ebedc5d32eccd6c3e54b7d9dcd12876a995ef47670"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.13/sp-darwin-amd64"
      sha256 "346880ca1cc911c393258e05ebec9710282fc8ea49828dad80805588e5409cd9"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.13/sp-linux-arm64"
      sha256 "220a8f7accf08b3357a5efd7a930ecf64d6f7e3aa0d46721d0cc60fcd2061436"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.13/sp-linux-amd64"
      sha256 "430e52b57a40e4055a6bb1aeeb416e16c43d68183a6f93f9714f816b9142d182"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
