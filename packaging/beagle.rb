# Homebrew formula (primary distribution channel, R1). Downloads the signed,
# per-platform binary from GitHub releases — no build from source, no
# post-install code fetch. Update url/sha256 per release (CI templates this).
class Beagle < Formula
  desc "Local transparency proxy for AI agents — see what they send, catch leaked secrets"
  homepage "https://github.com/boundedhq/beagle"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/boundedhq/beagle/releases/download/v0.1.0/beagle-darwin-arm64"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    else
      url "https://github.com/boundedhq/beagle/releases/download/v0.1.0/beagle-darwin-x64"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/boundedhq/beagle/releases/download/v0.1.0/beagle-linux-arm64"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    else
      url "https://github.com/boundedhq/beagle/releases/download/v0.1.0/beagle-linux-x64"
      sha256 "REPLACE_WITH_RELEASE_SHA256"
    end
  end

  def install
    bin.install Dir["beagle-*"].first => "beagle"
  end

  test do
    assert_match "beagle #{version}", shell_output("#{bin}/beagle --version")
  end
end
