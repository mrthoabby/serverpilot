class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.0.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.4/sp-darwin-arm64"
      sha256 "9a1139a33d2fc5eae9839eade52741d8c32079750e9e400a83ff9e34451bfd78"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.4/sp-darwin-amd64"
      sha256 "665931097ad076a8c2b0efd64a9cd76e36f624d68c63732bc7520cf41f7951fc"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.4/sp-linux-arm64"
      sha256 "ab8b7052eda3b9458e0ae5d43c0c97a5c76dd4d715fc1e5ab986a6ffe36cfaf5"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.0.4/sp-linux-amd64"
      sha256 "a295a68fa872291c9c21e75a2ea8a5f268f147b267c8ba38feb0a0fe0de9a0f7"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
