require "./spec_helper"
require "file_utils"
require "process"

# Interoperability tests against the latchset/jose CLI.
# Skipped automatically if `jose` is not on PATH.
private def jose_available? : Bool
  Process.run("which", ["jose"], output: Process::Redirect::Close, error: Process::Redirect::Close).success?
rescue
  false
end

private def with_tmpdir(&)
  dir = File.tempname("jose-interop")
  Dir.mkdir_p(dir)
  begin
    yield dir
  ensure
    FileUtils.rm_rf(dir)
  end
end

private def jose(args : Array(String), stdin : String? = nil) : {success: Bool, stdout: String, stderr: String}
  stdout_io = IO::Memory.new
  stderr_io = IO::Memory.new
  stdin_io = stdin ? IO::Memory.new(stdin) : Process::Redirect::Close
  status = Process.run("jose", args, input: stdin_io, output: stdout_io, error: stderr_io)
  {success: status.success?, stdout: stdout_io.to_s, stderr: stderr_io.to_s}
end

describe "Interop with latchset/jose" do
  unless jose_available?
    pending "skipped — `jose` CLI not on PATH"
    next
  end

  describe "JWK thumbprint (RFC 7638)" do
    it "matches jose's calculation for a P-256 keypair" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
      r = jose(["jwk", "thp", "-i-"], stdin: key.to_json(include_private: true))
      r[:success].should be_true
      key.thumbprint_base64url.should eq(r[:stdout].strip)
    end

    it "matches jose's calculation for a P-384 keypair" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P384)
      r = jose(["jwk", "thp", "-i-"], stdin: key.to_json(include_private: true))
      r[:success].should be_true
      key.thumbprint_base64url.should eq(r[:stdout].strip)
    end

    it "matches jose's calculation for a P-521 keypair" do
      key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
      r = jose(["jwk", "thp", "-i-"], stdin: key.to_json(include_private: true))
      r[:success].should be_true
      key.thumbprint_base64url.should eq(r[:stdout].strip)
    end
  end

  describe "JWS sign / verify cross" do
    it "Crystal signs (ES256) → jose verifies" do
      with_tmpdir do |dir|
        key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
        File.write("#{dir}/pub.jwk", key.public_key.to_json)
        jws = Jose::JWS.sign("interop payload", Jose::JWS::Algorithm::ES256, key)
        File.write("#{dir}/jws.txt", jws)

        r = jose(["jws", "ver", "-i", "#{dir}/jws.txt", "-k", "#{dir}/pub.jwk", "-O-"])
        r[:success].should be_true
        r[:stdout].should eq("interop payload")
      end
    end

    it "jose signs (ES512) → Crystal verifies" do
      with_tmpdir do |dir|
        key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
        File.write("#{dir}/priv.jwk", key.to_json(include_private: true))
        File.write("#{dir}/payload.bin", "signed by jose")

        r = jose([
          "jws", "sig", "-c",
          "-I", "#{dir}/payload.bin",
          "-k", "#{dir}/priv.jwk",
          "-s", %({"protected":{"alg":"ES512"}}),
          "-o-",
        ])
        r[:success].should be_true
        jws = r[:stdout].strip

        decoded = Jose::JWS.verify(jws, key.public_key)
        String.new(decoded).should eq("signed by jose")
      end
    end
  end

  describe "JWE encrypt / decrypt cross" do
    it "Crystal encrypts (P-256) → jose decrypts" do
      with_tmpdir do |dir|
        key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
        File.write("#{dir}/priv.jwk", key.to_json(include_private: true))
        jwe = Jose::JWE.encrypt("Tang-style payload", key.public_key)
        File.write("#{dir}/jwe.txt", jwe)

        r = jose(["jwe", "dec", "-i", "#{dir}/jwe.txt", "-k", "#{dir}/priv.jwk", "-O-"])
        r[:success].should be_true
        r[:stdout].should eq("Tang-style payload")
      end
    end

    it "Crystal encrypts (P-521) → jose decrypts" do
      with_tmpdir do |dir|
        key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
        File.write("#{dir}/priv.jwk", key.to_json(include_private: true))
        jwe = Jose::JWE.encrypt("payload P-521", key.public_key)
        File.write("#{dir}/jwe.txt", jwe)

        r = jose(["jwe", "dec", "-i", "#{dir}/jwe.txt", "-k", "#{dir}/priv.jwk", "-O-"])
        r[:success].should be_true
        r[:stdout].should eq("payload P-521")
      end
    end

    it "jose encrypts (P-256, ECDH-ES, A256GCM) → Crystal decrypts" do
      with_tmpdir do |dir|
        key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
        File.write("#{dir}/pub.jwk", key.public_key.to_json)
        File.write("#{dir}/payload.bin", "Tang round-trip")

        r = jose([
          "jwe", "enc", "-c",
          "-I", "#{dir}/payload.bin",
          "-k", "#{dir}/pub.jwk",
          "-i", %({"protected":{"alg":"ECDH-ES","enc":"A256GCM"}}),
          "-o-",
        ])
        r[:success].should be_true
        jwe = r[:stdout].strip

        plaintext = Jose::JWE.decrypt(jwe, key)
        String.new(plaintext).should eq("Tang round-trip")
      end
    end

    it "jose encrypts (P-521) → Crystal decrypts" do
      with_tmpdir do |dir|
        key = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P521)
        File.write("#{dir}/pub.jwk", key.public_key.to_json)
        File.write("#{dir}/payload.bin", "P-521 from jose")

        r = jose([
          "jwe", "enc", "-c",
          "-I", "#{dir}/payload.bin",
          "-k", "#{dir}/pub.jwk",
          "-i", %({"protected":{"alg":"ECDH-ES","enc":"A256GCM"}}),
          "-o-",
        ])
        r[:success].should be_true
        jwe = r[:stdout].strip

        plaintext = Jose::JWE.decrypt(jwe, key)
        String.new(plaintext).should eq("P-521 from jose")
      end
    end
  end

  describe "ECDH cross-derivation" do
    it "produces the same shared secret as jose jwk exc for P-256" do
      with_tmpdir do |dir|
        a = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
        b = Jose::JWK::ECKey.generate(Jose::JWK::Curve::P256)
        File.write("#{dir}/a-priv.jwk", a.to_json(include_private: true))
        File.write("#{dir}/b-pub.jwk", b.public_key.to_json)

        r = jose(["jwk", "exc", "-l", "#{dir}/a-priv.jwk", "-r", "#{dir}/b-pub.jwk", "-o-"])
        r[:success].should be_true
        # jose returns a JWK with a public point; the shared coordinate is
        # in the `x` field (the result of EC point multiplication).
        # Compare directly against Crystal's ECDH derive.
        jose_result = Hash(String, JSON::Any).from_json(r[:stdout].strip)
        jose_x = Jose::Utils.base64url_decode(jose_result["x"].as_s)

        crystal_z = Jose::JWE.ecdh_derive(a, b.public_key)
        crystal_z.should eq(jose_x)
      end
    end
  end
end
