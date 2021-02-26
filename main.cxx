#include "gui.h"

int main(int argc, char *argv[])
{
    Fl_Double_Window *win_main = make_window();

    win_main->show(argc, argv);

    Fl::run();

    return 0;
}
