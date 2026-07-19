class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.5.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.1/sp-darwin-arm64"
      sha256 "69e8f2c52ef01d42adb19f79648558e56b3010606310a6f9eb05d077a5256da5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.1/sp-darwin-amd64"
      sha256 "cb7a26283f2c6670f323fe318c8b5b31f3683392aa1dcd67a6e6c2095e099073"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.1/sp-linux-arm64"
      sha256 "f44aa6499b0c71a34c42610c6b80e84d5eb719bf70c1598b603791627f2d0d25"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.1/sp-linux-amd64"
      sha256 "e6391103ba2cc72103120c4d09f58f27bbf240078e61f948fc6b9fa7d55b8151"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
