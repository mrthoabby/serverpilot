class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.10.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.2/sp-darwin-arm64"
      sha256 "7f8e2d3e7204e4c901f4f9dc6ca3943abd30f99490fc5132a5dcaa8afc615de8"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.2/sp-darwin-amd64"
      sha256 "f208557faa67dabb0310095c15d78613ea3c26ee6610e1929af45f6bad6c047f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.2/sp-linux-arm64"
      sha256 "3d3dacbf77fb01f65e8ea837f85a113a7ddd5775172931b367c53f33fa9fc77c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.2/sp-linux-amd64"
      sha256 "6eebe9109da49c53738e994b680b4f3120fe1a152de22d8ebdc22b0940f785e0"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
