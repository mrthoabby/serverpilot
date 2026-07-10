class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-darwin-arm64"
      sha256 "9efd4a97fd4fa80827350183ade64433509969d820417b58c846fc4c1293ee6c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-darwin-amd64"
      sha256 "979f11b59c0c3f56f1eb3aaee7795a410e4d50c8573ba9211df5cf0b02b082fe"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-linux-arm64"
      sha256 "e6398d655494f89110b2f83ebc36cafcc9fca357d98f8132196df9b5a8909433"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0/sp-linux-amd64"
      sha256 "3dd3d5020f858996495b17012a2ca4b5afd517f77b8dc858b69ddbb1e8aafe1f"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
