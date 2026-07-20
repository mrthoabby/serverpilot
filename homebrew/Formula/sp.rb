class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.7.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.7.0/sp-darwin-arm64"
      sha256 "ded1060d2c0808a321bd1b1a92f20e7c60bd13884ef6024d24aa87185cbdaca8"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.7.0/sp-darwin-amd64"
      sha256 "2b92211194ee896d9f780fd14588d0a3444429a033161a0c1ca74d4bc450f8d5"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.7.0/sp-linux-arm64"
      sha256 "63c43ea5a77ee643b73956c44fa0f1b25ae0fd0ed88fe1d1ad23e7f2afea34e1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.7.0/sp-linux-amd64"
      sha256 "0fcaf61103b59cde832dfc5e6c383be3a3f9b2d920371a0fcd1ed65abaac1cf6"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
