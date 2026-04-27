class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-darwin-arm64"
      sha256 "c68d4fd4dc02043d96a8c35b10308283a07555fc95130ad48e7639f4b8abb98a"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-darwin-amd64"
      sha256 "7c4d71b41e76681d3749481599429b66cd5d1c2ad3e7877b7e346b0b2bad677f"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-linux-arm64"
      sha256 "434a8c53120069cebe156894809849b9ef086d8490efc8d9c6dca9bcd0d302b2"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0/sp-linux-amd64"
      sha256 "b4454593331cf55bf85671d907cf7678f729acc02d3133e9ee047dbb9a13eb92"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
