class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "2.9.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.0/sp-darwin-arm64"
      sha256 "9e36396a281ae4deb3dd113788f3bf4386646f7d75d9e3f2954c4ee31e17dfb1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.0/sp-darwin-amd64"
      sha256 "e9024c247ac3b3496b0093f16a5cc97cfae4aea4ab9e011281668b07a46a7b6d"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.0/sp-linux-arm64"
      sha256 "e1db88a720b0859817745906ae302bf3b87c15e2de8621c3e1f6bdfa3459a950"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/2.9.0/sp-linux-amd64"
      sha256 "9473195033a15ae94b4046161e62665bae8503fd10ce565553db01c604bb5f42"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
