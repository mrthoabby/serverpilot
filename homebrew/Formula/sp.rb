class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.9.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.4/sp-darwin-arm64"
      sha256 "c4a14112ff89ccd76a8ebee51a5f469fe42562dd6e3923590cde50444ead4fe2"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.4/sp-darwin-amd64"
      sha256 "71874dc42177e0c696fa5ed1c82f013d1be21439201a6d65f8d43ddddf062efb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.4/sp-linux-arm64"
      sha256 "0509c1197b601f3dd20ce1bb10aca9b9b36b5547821eb58a8f5ed8f31a29b646"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.4/sp-linux-amd64"
      sha256 "96d0816b7f843986d3c7dfe0c0d9390dc5adc339b20b4b07edc373e542bf39c5"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
