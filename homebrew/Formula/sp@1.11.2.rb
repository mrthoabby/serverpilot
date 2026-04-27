class SpAT1.11.2 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.11.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.2/sp-darwin-arm64"
      sha256 "9677b54f2a962ec5f81284411cf169babc3e1dbe3ed056e3c0d961143a2aa6b9"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.2/sp-darwin-amd64"
      sha256 "23d072e3ab58b55bf844a893e9900f991a7d8cc523b6f9dcde4cc8d290753e1f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.2/sp-linux-arm64"
      sha256 "9440630b23a00a00d3e089a256a217c3c4ce264337614146f70bd03f9f4ce6f7"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.11.2/sp-linux-amd64"
      sha256 "f0d20dc972ecc2e54d57d529c85cf89ae4a8ce767389da83be98fa28b041b2be"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
