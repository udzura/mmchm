file :mruby do
  sh "git clone --depth=1 git://github.com/mruby/mruby.git"
end

SECCOMP_VERSION = ENV['SECCOMP_VERSION'] || "v2.3.2"
file :libseccomp do
  sh "git clone https://github.com/seccomp/libseccomp.git"
  Dir.chdir("libseccomp") { sh "git checkout #{SECCOMP_VERSION}" }
end
