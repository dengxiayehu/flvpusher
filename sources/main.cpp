#include <memory>

#include "app/app.h"
#include "common/config.h"

using namespace flvpusher;

int main(int argc, char *argv[])
{
  ABS_PATH(argv[0], abs_program, sizeof(abs_program));

  std::auto_ptr<App> app(App::get_instance());
  return app->main(argc, argv);
}
