class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.11"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.11/sp-darwin-arm64"
      sha256 "efc43e4eddd80ecc9b9b0f3367adeb245af7de6b75961f9794e882a80bf635dd"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.11/sp-darwin-amd64"
      sha256 "8b9d5e218318a45f4ff3476fca7b0d8a8f97482d1af459497e89087a49186950"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.11/sp-linux-arm64"
      sha256 "47b6d6902d349dee26110bd75de2aac68456b91b6fb0ec1422fc0d5f899f5bf0"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.11/sp-linux-amd64"
      sha256 "9d5caa06367e4d36c2199e7b0d9cbd127f7dc6aa60690bf4e130db9b1cca97e0"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
