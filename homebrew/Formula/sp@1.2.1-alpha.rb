class SpAT1.2.1-alpha < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.2.1-alpha"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.1-alpha/sp-darwin-arm64"
      sha256 "4bb8b7eef0d24551ed49094101923b2465aed5d5a76453e59dd8b9068aa2d999"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.1-alpha/sp-darwin-amd64"
      sha256 "b4c5129adff14f7778582f7fc33e9eb8a1a068fa544f3f4d83a627445fe8df30"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.1-alpha/sp-linux-arm64"
      sha256 "830f9227bab163537333e87700f182535352133525a04d920d24fbabe9e413a7"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.2.1-alpha/sp-linux-amd64"
      sha256 "67e9fdd038318c2971a3cef8c39db6def2c4d32fa48edf68dd6cb5c055e425a8"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
