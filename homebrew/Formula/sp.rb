class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.5.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-darwin-arm64"
      sha256 "73bd34e6c7ff5cc3f9396fc5eb4d985a36de16ae3870b5a83033dbcca13ecacb"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-darwin-amd64"
      sha256 "0a39c94551fdf3eb6ad8c280f6a8b15fbc36755909b86ed1a6042a8a4130d4dc"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-linux-arm64"
      sha256 "f43bd7a75e6d44455f952406a16836672912ecab1b15b013f350854b9b783c95"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.5.0/sp-linux-amd64"
      sha256 "3b91fd5d5be514daa9ea3b5f8830a541cc2f2174a41e17cf8d947c159db276aa"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
