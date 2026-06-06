class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.5"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.5/sp-darwin-arm64"
      sha256 "f7bafea501e48d01e3676d4abcd8de03729bd30bcb3b3f75521e9a186df6716b"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.5/sp-darwin-amd64"
      sha256 "d263c1ebe58bc967c855278bbe19ed1a63a72c386dbb60846f35eac4e51c78de"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.5/sp-linux-arm64"
      sha256 "2c69e85eccbc7c51419b6a296fd0cfd86b232fc2373706743b9a59926f1e03b2"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.5/sp-linux-amd64"
      sha256 "9ce23a2cbfcba7d5ef34e56c62653a2a6d053858809038f6ae2d56bcb0ea2d23"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
