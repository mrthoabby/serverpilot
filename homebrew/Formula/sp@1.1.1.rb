class SpAT1.1.1 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-darwin-arm64"
      sha256 "f278b06d9e23b8007d3d34823f89e76670faf112c12ec11ff97a87eb99e25822"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-darwin-amd64"
      sha256 "8bcbf4cde6a4d8a934c1893bb0ab7ffc4fa743bd91efee2d11708de4cb6dfb1a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-linux-arm64"
      sha256 "9ee5798e1bd5243151edfdd2cdf4aa78639ef5f09758b36a8f6fe086fbe56bce"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.1/sp-linux-amd64"
      sha256 "b35e05f509fd78a1a49752b61be438749b2aff5d74e0e6508f586e8b90608109"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
