class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mercadolibre/serverpilot"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mercadolibre/serverpilot/master/release/1.0.0/sp-darwin-arm64"
      sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    else
      url "https://raw.githubusercontent.com/mercadolibre/serverpilot/master/release/1.0.0/sp-darwin-amd64"
      sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mercadolibre/serverpilot/master/release/1.0.0/sp-linux-arm64"
      sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    else
      url "https://raw.githubusercontent.com/mercadolibre/serverpilot/master/release/1.0.0/sp-linux-amd64"
      sha256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
