class SpAT1.1.0-alpha < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.0-alpha"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0-alpha/sp-darwin-arm64"
      sha256 "04b6d8fd78daf4c4a71b7b42da826dff0f47c476d0f5815b6c4c0341513d2695"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0-alpha/sp-darwin-amd64"
      sha256 "c2b176776906536b1ca5271e4d903aab1f665e19d39168b763cc8d796dbd072d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0-alpha/sp-linux-arm64"
      sha256 "db71dc5d271308635d97ee6b01f6f762f522111e474a3fc61773b47db22c9a7e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.0-alpha/sp-linux-amd64"
      sha256 "c98cd19f22210950397b3aae37a56d2a163936fcd5b208cd78e9e7357d462a68"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
