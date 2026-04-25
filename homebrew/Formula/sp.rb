class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.8.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.8.0/sp-darwin-arm64"
      sha256 "cb6fd68ab4da4902bcecd1e9350bfd8d4d8771e5900daedc17dfdfcac1ae98fd"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.8.0/sp-darwin-amd64"
      sha256 "d7a7523a7277d6279a3351198fd4f7981bb4f1d61b1e62a6a735581e39b0b7ac"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.8.0/sp-linux-arm64"
      sha256 "efd1347551d23f5caf2eb8bbc8e7e76769d8c491955e655abafc863561d43ac1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.8.0/sp-linux-amd64"
      sha256 "6bb8a4a6ce344fac23a53fa8a9df274b1c30091c4be3f1d4d09bad1134ed5c00"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
