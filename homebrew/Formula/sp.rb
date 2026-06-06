class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.9"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.9/sp-darwin-arm64"
      sha256 "c21b23994b8273c228812376a25ef857ed8bb6259554e05fb92e26c703e917c1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.9/sp-darwin-amd64"
      sha256 "bc9a7b5f9b4e2fcf45ca2139eba8ecec764def2c05a1844d9931e23234d56c46"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.9/sp-linux-arm64"
      sha256 "e96d81281ff314708e7f74375598b481ff20bd05dc76df6b0c2d947e98b42224"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.9/sp-linux-amd64"
      sha256 "b4635fb6e663fa1e712199743b4c2a5ef95661e18ee1ccdcb6b0fe2a44cf24de"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
