class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.15"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.15/sp-darwin-arm64"
      sha256 "685a5915b0666fbf2b239f4bbd7cd00ad761ff43b70125cdfdf788d999cce7aa"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.15/sp-darwin-amd64"
      sha256 "113fa9187dd9642cbc348d7964805d67e428ecd5f32bba7eb3f6e8ef0749ed7a"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.15/sp-linux-arm64"
      sha256 "f49fed73f7971ae0bc711ca54bc0569fed138781a0982e0a9cc31ef407f14901"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.15/sp-linux-amd64"
      sha256 "9af4da8d504e589c3f136687cb1956f94e8dd4f00c2c57cfe49daaee8f570bc5"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
