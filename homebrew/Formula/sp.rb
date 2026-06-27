class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.20"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.20/sp-darwin-arm64"
      sha256 "97cc0770d6b742f61e69becb633735f90639fbb2833969c2a5ca9aa1a07eb370"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.20/sp-darwin-amd64"
      sha256 "36da1dc41957f65a83761dfbc1c4d0183cc95bab4d5f09a19e2aecb4396d0b63"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.20/sp-linux-arm64"
      sha256 "83a662864406486a035817b1c496f9b60bf44a4e5c9ac046fc432d97702f8d47"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.20/sp-linux-amd64"
      sha256 "4173683462b3dee020193cf6ddb0b59c492f0bf65f972c678000736755f13142"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
