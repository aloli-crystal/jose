require "./spec_helper"
require "file_utils"
require "process"

# Interoperability tests for RSA against the `openssl` binary.
# Skipped automatically if `openssl` is not on PATH.
#
# RSASSA-PKCS1-v1_5 is deterministic: for a given key, digest and input there
# is exactly one correct signature. Comparing our bytes to OpenSSL's is
# therefore a complete check of padding, digest and key handling at once —
# not merely a round-trip against ourselves.
private def openssl_available? : Bool
  Process.run("which", ["openssl"], output: Process::Redirect::Close, error: Process::Redirect::Close).success?
rescue
  false
end

private def with_tmpdir(&)
  dir = File.tempname("jose-rsa-interop")
  Dir.mkdir_p(dir)
  begin
    yield dir
  ensure
    FileUtils.rm_rf(dir)
  end
end

private def openssl(args : Array(String)) : {success: Bool, stdout: String, stderr: String}
  stdout_io = IO::Memory.new
  stderr_io = IO::Memory.new
  status = Process.run("openssl", args, output: stdout_io, error: stderr_io)
  {success: status.success?, stdout: stdout_io.to_s, stderr: stderr_io.to_s}
end

describe "Interop with openssl (RSA)" do
  unless openssl_available?
    pending "skipped — `openssl` not on PATH"
    next
  end

  describe "key material" do
    it "emits a SubjectPublicKeyInfo openssl can read" do
      with_tmpdir do |dir|
        key = Jose::JWK::RSAKey.generate(2048)
        File.write("#{dir}/pub.der", key.public_key.to_spki_der)

        r = openssl(["pkey", "-pubin", "-inform", "DER", "-in", "#{dir}/pub.der", "-text", "-noout"])
        r[:success].should be_true
        r[:stdout].should contain("Public-Key: (2048 bit)")
      end
    end

    it "emits a PKCS#8 private key openssl can read" do
      with_tmpdir do |dir|
        key = Jose::JWK::RSAKey.generate(2048)
        File.write("#{dir}/priv.der", key.to_pkcs8_der)

        r = openssl(["pkey", "-inform", "DER", "-in", "#{dir}/priv.der", "-text", "-noout"])
        r[:success].should be_true
        r[:stdout].should contain("Private-Key: (2048 bit")
      end
    end
  end

  describe "signature agreement" do
    {
      {Jose::JWS::Algorithm::RS256, "sha256"},
      {Jose::JWS::Algorithm::RS384, "sha384"},
      {Jose::JWS::Algorithm::RS512, "sha512"},
    }.each do |algorithm, digest|
      it "produces byte-identical #{algorithm.name} signatures to openssl" do
        with_tmpdir do |dir|
          key = Jose::JWK::RSAKey.generate(2048)
          File.write("#{dir}/priv.der", key.to_pkcs8_der)

          jws = Jose::JWS.sign("interop payload", algorithm, key)
          header_b64, payload_b64, signature_b64 = jws.split('.')
          File.write("#{dir}/input.bin", "#{header_b64}.#{payload_b64}")
          ours = Jose::Utils.base64url_decode(signature_b64)

          r = openssl([
            "pkeyutl", "-sign",
            "-inkey", "#{dir}/priv.der", "-keyform", "DER",
            "-digest", digest, "-rawin",
            "-in", "#{dir}/input.bin", "-out", "#{dir}/theirs.sig",
          ])
          r[:success].should be_true

          theirs = File.read("#{dir}/theirs.sig").to_slice
          theirs.size.should eq(256)
          ours.should eq(theirs)
        end
      end
    end
  end

  describe "verification cross-check" do
    it "verifies a signature openssl produced" do
      with_tmpdir do |dir|
        key = Jose::JWK::RSAKey.generate(2048)
        File.write("#{dir}/priv.der", key.to_pkcs8_der)

        header_b64 = Jose::Utils.base64url_encode(%({"alg":"RS256"}))
        payload_b64 = Jose::Utils.base64url_encode("signed by openssl")
        signing_input = "#{header_b64}.#{payload_b64}"
        File.write("#{dir}/input.bin", signing_input)

        r = openssl([
          "pkeyutl", "-sign",
          "-inkey", "#{dir}/priv.der", "-keyform", "DER",
          "-digest", "sha256", "-rawin",
          "-in", "#{dir}/input.bin", "-out", "#{dir}/sig.bin",
        ])
        r[:success].should be_true

        signature = File.read("#{dir}/sig.bin").to_slice
        jws = "#{signing_input}.#{Jose::Utils.base64url_encode(signature)}"

        String.new(Jose::JWS.verify(jws, key.public_key)).should eq("signed by openssl")
      end
    end
  end
end
