file :mruby do
  sh "git clone --depth=1 git://github.com/mruby/mruby.git"
end

SECCOMP_VERSION = ENV['SECCOMP_VERSION'] || "v2.3.2"
file :libseccomp do
  sh "git clone https://github.com/seccomp/libseccomp.git"
  Dir.chdir("libseccomp") { sh "git checkout #{SECCOMP_VERSION}" }
end

file 'vendor/lib/libseccomp.a' => :libseccomp do
  Dir.chdir('./libseccomp') do
    sh './configure --enable-static --disable-shared --prefix=`pwd`/../vendor'
    sh 'make'
    sh 'make install'
  end
end

file :mmchm do
  sh %q[ env CFLAGS='-I./vendor/include -lseccomp' LDFLAGS='-L./vendor/lib' make mmchm ]
end
