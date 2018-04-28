.SUFFIX:.h .cpp .out

sender.out:main.cpp IcmpManager.cpp IcmpManager.h
	g++ -o $@ main.cpp IcmpManager.cpp -I. -std=c++11