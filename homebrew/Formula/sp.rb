class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.2.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.2.0/sp-darwin-arm64"
      sha256 "39559cb82f1c2ddcd6c491739862f36b96eaa11a661ed93c21083b9628ce64dd"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.2.0/sp-darwin-amd64"
      sha256 "9aa39fd20beeaf07446bef92bc56b66a30fde1cae42bd640e599de1bd223f0fb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.2.0/sp-linux-arm64"
      sha256 "4b5589e0258a06e1388399a2ab2d8b434dbb0bb69bdc2bab9d84e02931966e05"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.2.0/sp-linux-amd64"
      sha256 "a22f7539001bf54bf48a97f98c532d12d984efe6eac806980d4c71214c301fd6"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
