#include "common/parent.h"

int main(int argc, char* argv[]) {
	setup_parent("shm", argc, argv);
	setup_parent("tcp", argc, argv);
}
