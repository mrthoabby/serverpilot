class SpAT1.12.1 < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.12.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.1/sp-darwin-arm64"
      sha256 "d2631e8348af1d1ed475a022499c65833a40997104326aae513e9dc261ff0e83"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.1/sp-darwin-amd64"
      sha256 "32d87e47f97cb9ada9387cece095941a2ba15c82121b20a8dd23da96858e7e04"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.1/sp-linux-arm64"
      sha256 "e4bbbdddd50043d051c432cbe533e4c2488eaf9f65783e3bab7932dd5cf5b5ab"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.12.1/sp-linux-amd64"
      sha256 "f9a09ca26ba77b1801db529162ffd87fa35e5642c19977896537e909560d4b27"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
