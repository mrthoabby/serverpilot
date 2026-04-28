class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.4/sp-darwin-arm64"
      sha256 "1fcabb88188e2c5fbf2787f66333006a905c63b0dc12480b40cf494daa5626ad"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.4/sp-darwin-amd64"
      sha256 "24ac4c487b64ea2085dc118a7389973ee262761dfc208d1807820964d32e50cb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.4/sp-linux-arm64"
      sha256 "122e4a6d49d86498e952541a40bae1ca8ef2f75ed43970c2c328afcba049b106"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.4/sp-linux-amd64"
      sha256 "0c14210722a4647befc2228d0216d4b7642d88ed86b25fd428bf646e8010b684"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
