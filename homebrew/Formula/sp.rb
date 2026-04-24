class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.0-alpha"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0-alpha/sp-darwin-arm64"
      sha256 "cffd26daa70182e45c8496f461f05268ea16d358f821339e4f87605e0ca4eca6"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0-alpha/sp-darwin-amd64"
      sha256 "89fa2f29ef103124f0702be027f511f7f6cfb96ae3aca98ab9c9411c72276afa"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0-alpha/sp-linux-arm64"
      sha256 "d00bc031568c64b62fd05112ea449c0d74d626b1b1883de09dbb1ff22f021ab1"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.0-alpha/sp-linux-amd64"
      sha256 "449c06bc670205c16f63d7e2c0778437baf690560df2a062dd3e54f09c4645f5"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
