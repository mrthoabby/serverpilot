class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.6"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.6/sp-darwin-arm64"
      sha256 "943bd662198099f63625d922250ada0046f25fac2f3ea93a40e46eadcccde99d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.6/sp-darwin-amd64"
      sha256 "e9e33f94ab323cfa8205dcf08bc5d13fb55b3505b219ef77ebe3778598a77bcd"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.6/sp-linux-arm64"
      sha256 "2c1e10fca6d32dc4ea2862574a02cac52f3c018613a19051815b3adc8f145a6e"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.6/sp-linux-amd64"
      sha256 "7571c2d61bc50c300b58482bfe676b956efea3e4b297165a403113e262b41d97"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
