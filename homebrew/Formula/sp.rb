class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.4/sp-darwin-arm64"
      sha256 "873c6bea2f8017e672cc24b9407b4098f6dbeb78d842120142f65c7279af419f"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.4/sp-darwin-amd64"
      sha256 "85c3ac7728037402f9dd5fb65cc518f36c50758a7d18d1ad5cd3b58793751494"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.4/sp-linux-arm64"
      sha256 "cc364bc1677dbb1565f82a4f8229280c7796030ff05bc7501b4eec3ba1f1415a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.4/sp-linux-amd64"
      sha256 "cc803999b63066b38698fb315eedc3f98f3633f311dcf82460386a93e32bd7f1"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
