class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.1.0/sp-darwin-arm64"
      sha256 "b6b96b98076035fece512c85eb4765a5e98ed65040c27b4605b06cb68067c52a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.1.0/sp-darwin-amd64"
      sha256 "8ab9d386462514910415b05e292c642fe118c19d774484f4b30f90e37872e49f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.1.0/sp-linux-arm64"
      sha256 "523a08325b6ef2ab8457c7c7b6f85ea84e2ef9cb01f183c6399bd03f199d300b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.1.0/sp-linux-amd64"
      sha256 "d3bd89104b9d2d4a33452315bb60ba6a53b40376dd8c73b06055f50f1e5ccd1d"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
