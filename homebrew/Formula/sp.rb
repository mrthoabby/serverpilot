class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.1.9"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.9/sp-darwin-arm64"
      sha256 "297f9da5091923a0bd106498689bcf3c111f37c66af0fffa7c0ebcf98393926a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.9/sp-darwin-amd64"
      sha256 "fab23af885aa5e5e20a36afe68dc394c04214ffb307efd48e115829ada8c44d0"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.9/sp-linux-arm64"
      sha256 "66a368f8c087d68d9313837cec7aaf8c4d2a90662449e1fde130a19b39854e82"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.1.9/sp-linux-amd64"
      sha256 "b2dd6e110349a0e9b9f71ccb781cb07222f064d0810b3750220adaa10b167cc8"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
