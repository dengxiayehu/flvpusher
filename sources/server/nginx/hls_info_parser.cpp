#include <memory>

#include "../../xutil/xutil.h"
#include "../../xutil/xfile.h"

using namespace xutil;
using namespace xfile;
using namespace std;

/* currently we only care about m3u8's access-time */

int main(int argc, const char *argv[])
{
  if (argc != 2 ||
      basename_(argv[1]) != "hls_info.txt") {
    goto bail;
  }

  BEGIN
  AutoFileLock _l(argv[1]);

  auto_ptr<File> f(new File);
  if (!f->open(argv[1], "rb")) {
    goto bail;
  }

  BEGIN
  uint64_t access_time;
  f->seek_to(1024 + 1);
  f->readui64(&access_time);

  uint64_t now = get_time_now();
  printf("%ld", (long) (now - access_time)/1000);
  END
  END

  return 0;

bail:
  printf("-1");
  return -1;
}
