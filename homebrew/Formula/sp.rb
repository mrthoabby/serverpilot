class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.9.1"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.1/sp-darwin-arm64"
      sha256 "a89df9ba949ae83587b6ca03019c366c8a235c48816b2dcd39e8a753c780ac25"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.1/sp-darwin-amd64"
      sha256 "39cac8ed66564f07bfc1728e7a2dddcb7d1ad5085a526e2050b531da314de5db"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.1/sp-linux-arm64"
      sha256 "12799479671cbe51d20857ba1582d70fabaa712f9db60cfaa8fef633853742ef"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.1/sp-linux-amd64"
      sha256 "948a16aa6681b48e71169a63d7e6cbe5c245ef2ecb364c2b5a58bc1de8e7debd"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
