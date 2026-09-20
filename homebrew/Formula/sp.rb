class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "3.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.1.0/sp-darwin-arm64"
      sha256 "cdb8a556e77f6a5ba039f08e2b32b1f05c5939db2332c0362a740250c846fe8e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.1.0/sp-darwin-amd64"
      sha256 "a79b5beddf5f479b651c8bc45d0e87a9cd9bdf73d922439912c3097925db8b20"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.1.0/sp-linux-arm64"
      sha256 "86f2310954dca38126fa9f47e3314c67872a354497567e6a1e17b4091556fd1d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/3.1.0/sp-linux-amd64"
      sha256 "0f81647431a9d30493ce105e40427dfdd1c9fad4a1b9fc48b95d3847b611f7f7"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
