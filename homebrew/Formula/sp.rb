class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.8"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.8/sp-darwin-arm64"
      sha256 "f8678a721d5382a9c19121859163b305e494bc9843541c042951a13a0bba342f"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.8/sp-darwin-amd64"
      sha256 "c1d1251ad1c714d22c6ade0034691734d5edc3e52759b56543e111a6715c8d3a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.8/sp-linux-arm64"
      sha256 "c93a4ea5a48c4a509a101028aed0d251cbda52766cc70b23d3ba910aa9b1f3e6"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.8/sp-linux-amd64"
      sha256 "7cf7396c79c762c00f1ff8140c4f21189c4801d3591219c4d8426cd259d2a305"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
