class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.4.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.4/sp-darwin-arm64"
      sha256 "6ff930a277b89fc7c2c273acd7c52e4dc8b427206489dfdf3be349338794b1f7"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.4/sp-darwin-amd64"
      sha256 "7c40bd1e51bda441b93d4e877ef3f336368534f4a00ed4c2953b956fc9ebe2bb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.4/sp-linux-arm64"
      sha256 "fb91423b7aa8135631341d434a7993a707f16f7fabe5f4cb674328794f767754"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.4.4/sp-linux-amd64"
      sha256 "dfca07d9a73bc46f8e9b4605dd83d952e900448ec642d67b85ff148aede5cfed"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
