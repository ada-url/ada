## Amalgamation demo

While in the ada main directory, using Python 3, type:

```
python singleheader/amalgamate.py
```

This will create two new files (ada.h and ada.cpp).

You can then compile the demo file as follows:

```
c++ -std=c++17 -c demo.cpp
```

It will produce a binary file (e.g., demo.o) which contains ada.cpp.

```
c++ -std=c++17 -o demo demo.cpp
./demo
```

You may build and link using CMake (--target demo), because CMake can configure all the necessary flags.


### C Demo

You may also build a C executable.

```
c++ -c ada.cpp -std=c++17
cc -c demo.c
c++ demo.o ada.o -o cdemo
./cdemo
```
