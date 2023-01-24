While in the ada main directory, using Python 3, type:

python singleheader/amalgamate.py

This will create two new files (ada.h and ada.cpp).

You can then compile the demo file as follows:

c++ -std=c++17 -c demo.cpp

It will produce a binary file (e.g., demo.o) which contains ada.cpp.

It remains to link with libicuuc and libicui18n. This is specific to your system.