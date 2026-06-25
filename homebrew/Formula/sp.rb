class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.3/sp-darwin-arm64"
      sha256 "612493fc04534ec70fcbca50b4b54ecc10a48b06bb549a17dfcbbb030159259b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.3/sp-darwin-amd64"
      sha256 "ef0769b2e8b0d24a3803959271711db7626542d77534c97d04bc98c976763a1c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.3/sp-linux-arm64"
      sha256 "4ae2d85d3e652654f1410100ee5f8d3959caad57246f3a87470819faa5528af5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.3/sp-linux-amd64"
      sha256 "4568fdf8b8a2a8b5d3436cf7788888ae33756493c8eb6ee9600b1be1b2b5a755"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
