class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.7.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.0/sp-darwin-arm64"
      sha256 "9ef0ddc00b9744afa2be216cda920a3e30830bf503d106b46064ad322c9808f4"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.0/sp-darwin-amd64"
      sha256 "a2e5cf0797b593fa8277cea86d6346b667378c2961f5829456c4c9b38bd290b5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.0/sp-linux-arm64"
      sha256 "ec0f71a694c73587423b60b48c2f91352ced77a674b7d3b6fc1efde3fb265124"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.7.0/sp-linux-amd64"
      sha256 "0b444ea89887e5cfc0a886e8b3076d0e826f263ef68d8f43e39aa33e5fc90a4e"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
