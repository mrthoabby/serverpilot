class SpAT1.10.3 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.10.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.3/sp-darwin-arm64"
      sha256 "92700288441ebe487d7e6f6c8265af2ffda007ba117f90dff014b4756cab6b1f"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.3/sp-darwin-amd64"
      sha256 "dd13683f08313c9463f0e188a06ff1e91c03d681bdd1efd79123af5c8350b5d8"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.3/sp-linux-arm64"
      sha256 "1f4f1e19d8229f2e074b4d909143b6c55ecf7859bc7ec4ee300707cafd36149d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.10.3/sp-linux-amd64"
      sha256 "4327991a3256d63ef7ff4cc4b7fed73e07f5c18f970b4f3133d035cac76d6579"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
