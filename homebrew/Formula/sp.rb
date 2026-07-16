class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.0.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.3/sp-darwin-arm64"
      sha256 "933025c093548713ff166da715700044bfff6df78c172b78eeb0512dec3fc21c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.3/sp-darwin-amd64"
      sha256 "588b363108be31adfb4ce27a837b6b18a51b70bd7eb19d4a77c398e3c7a90afa"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.3/sp-linux-arm64"
      sha256 "863c34e7766bdffeeda5d8d16cb24b5bb30bf28e6b99428c10c92ac113ac179b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.3/sp-linux-amd64"
      sha256 "1c078b9359138063fdc1c2b0de6a1edde63865df77cce856b2ec1eaac6de4286"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
