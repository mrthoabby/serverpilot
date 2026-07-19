class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.5.3"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.3/sp-darwin-arm64"
      sha256 "bce6fed93aa2ddab37013fd30788be7db714a1ea3c0c7087238c440b5b3e9f22"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.3/sp-darwin-amd64"
      sha256 "a146dae4e9907ab732534f115245c39818842ce0becf710d4fff9e60c8e8083c"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.3/sp-linux-arm64"
      sha256 "6e7d770338a42d9a837665b9055677a54c888c4e6998621b98fa774d7635a21d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.3/sp-linux-amd64"
      sha256 "a1d81442466c2a2538786e02bc89d97cb758f773b460428f1825765a5edc913f"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
