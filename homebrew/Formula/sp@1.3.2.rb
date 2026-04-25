class SpAT1.3.2 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.3.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.2/sp-darwin-arm64"
      sha256 "afbc1611150ed7224824b4684c2912ff7a15e0c0b07a07076078b12d01ba5447"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.2/sp-darwin-amd64"
      sha256 "9123e3dacd893e155085de521d4c768ae15cb834dac52f76c13b1746bea80b57"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.2/sp-linux-arm64"
      sha256 "51d0684823374865c5ecc6c540146edd5c6bc8b37888e11ec20964b90283aaae"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.3.2/sp-linux-amd64"
      sha256 "5681f15de531aaebc490b3a457df25f9a22a796425d55a0212c860bd55f53b8d"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
