#include <memory>

#include "app.h"

using namespace flvpusher;

int main(int argc, char *argv[])
{
    std::auto_ptr<App> app(App::get_instance());
    return app->main(argc, argv);
}
