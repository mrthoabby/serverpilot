class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.5/sp-darwin-arm64"
      sha256 "96fbae1f6fc80eda0def809f8c59262e5cb0f0c8254277103c2869ac9574d9e6"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.5/sp-darwin-amd64"
      sha256 "e9b489c0ddfc95fa461950c8867d81976f07fdf5a314796010f14affcbf7f9a3"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.5/sp-linux-arm64"
      sha256 "0ae4be9dc12da82bb3086050ef76c406cd96a50169201415ee1cb01e8c9c74c1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.5/sp-linux-amd64"
      sha256 "35de4ab8fc6acc2fdc66c0f2ffb71b16bef2b69917641f84314d4b07485f06f3"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
