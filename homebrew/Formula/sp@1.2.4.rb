class SpAT1.2.4 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.2.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.4/sp-darwin-arm64"
      sha256 "04b3018c9414845c6132410518214c7a34c2a4af1c1eaf844c6be55bd01cb08a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.4/sp-darwin-amd64"
      sha256 "628b4404cb81819d64e6c47995dd0a72f7f2ad3161859003a54784dfd59c1119"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.4/sp-linux-arm64"
      sha256 "f7116e808294ebb243b796634ce79eda3cc8841bce52663a6ead4a31cf6c94d6"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.4/sp-linux-amd64"
      sha256 "3d85c46f7968af7a3760709c1d6d75a8963ea5bbb6916b32023e4ca6422ec440"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
