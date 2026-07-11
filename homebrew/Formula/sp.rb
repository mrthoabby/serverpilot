class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.11"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.11/sp-darwin-arm64"
      sha256 "ac23c6a5e935e12e216ce5cb67b33d2ed77695ace7944cc4cf1032270dda131b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.11/sp-darwin-amd64"
      sha256 "0034cd9fd422b69ddd4ef4979bfa6a2c6f9eed50d8af829f49564566fb5a9571"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.11/sp-linux-arm64"
      sha256 "4378ac44c0aed5a6cfdd1ba4ac64b3bb7ca4cd4dba54131d04be340c68cd2137"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.11/sp-linux-amd64"
      sha256 "ed27d1a8bc28a3c71febd5ab553d86dad43449e405a2d308351b892eca0ae7f1"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
