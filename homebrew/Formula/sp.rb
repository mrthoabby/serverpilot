class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.6.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.6.0/sp-darwin-arm64"
      sha256 "71d9216b47c875bbdb5b4daf39275a06c8408b9764b04827f4f0af834ff921d7"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.6.0/sp-darwin-amd64"
      sha256 "3a912c6799d55afa6a0eee3f1407870421116374741db51f5d0853a38cb0727c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.6.0/sp-linux-arm64"
      sha256 "2f6619e714f8c335e023b87015353f873f513a2772703da40a531a809061b736"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.6.0/sp-linux-amd64"
      sha256 "5a996d3e02755d30bb922e150f814011a7843a37edb83e85f766c17525d65267"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
