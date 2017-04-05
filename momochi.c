#include <unistd.h>

int main(int argc, char **argv)
{
  execl("/usr/bin/ruby", "ruby-test", "-e", "loop { puts 'hi'; sleep 1}", (char *)NULL);
  return 127;
}
