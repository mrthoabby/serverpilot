class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.5.2"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.2/sp-darwin-arm64"
      sha256 "8da0bff81b92a22c394d0a08939cc3db27b03aaf5dff542c3e291709327e0cec"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.2/sp-darwin-amd64"
      sha256 "eb15848b95b91e297f332d17b1667b6de41ba9198c50df7d19504b6e750ce8d6"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.2/sp-linux-arm64"
      sha256 "83cb1ff26d30b0495747120e2f029dfa0c3b58e1faff3a80de947f4db3bbe9fd"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.5.2/sp-linux-amd64"
      sha256 "5871edcb03efe29769de778fcf1aefbd60538b90f4545922f442b66be8bf6e9a"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
