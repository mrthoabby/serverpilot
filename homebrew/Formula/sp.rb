class Sp < Formula
  desc "Server management dashboard for Docker & Nginx"
  homepage "https://github.com/mrthoabby/serverpilot"
  version "1.0.4"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.4/sp-darwin-arm64"
      sha256 "d36042fa9ddc58adf603daec8053f721b5c94af0755762c0ab66e290ab72312d"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.4/sp-darwin-amd64"
      sha256 "5af7b7c8c5574992a677ffc4294a068c60906701665de1662cb77c1dbf754ceb"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.4/sp-linux-arm64"
      sha256 "26bd5afb441683662b8863a5e524857ca69246685923d46f2aa3f4eb13068f3c"
    else
      url "https://raw.githubusercontent.com/mrthoabby/serverpilot/master/release/1.0.4/sp-linux-amd64"
      sha256 "15bbf835d18db084b3d8da78988708873100ce26cda2d492a7977d370b415071"
    end
  end

  def install
    bin.install Dir["sp-*"].first => "sp"
  end

  test do
    system "#{bin}/sp", "version"
  end
end
