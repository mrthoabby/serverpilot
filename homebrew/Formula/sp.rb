class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.27"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.27/sp-darwin-arm64"
      sha256 "8462829ecdafd3b74e9d3ae3ea6cb4def43ddaeda4f5a108c93363ee69dc6727"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.27/sp-darwin-amd64"
      sha256 "2a7a2df3f9a912dee5900b7f6cce6076678ea2f97f2bc4bc30afb07fe854cc4e"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.27/sp-linux-arm64"
      sha256 "4d5c99cc1d5e20026b9a23076875a48e1d7f6afb0370f44b98a01792c7f62e98"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.27/sp-linux-amd64"
      sha256 "4224be4feddd9cc3e8c32494380124e65275aaedecd32c72a8df83ee07dea57a"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
