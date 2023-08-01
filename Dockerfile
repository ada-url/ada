FROM debian:12-slim@sha256:89468107e4c2b9fdea2f15fc582bf92c25aa4296a661ca0202f7ea2f4fc3f48c

RUN apt-get update && apt-get install -y \
    apt-transport-https \
    gcc \
    clang \
    clang-tools \
    cmake

WORKDIR /repo

CMD ["bash", "-c", "cmake -B build && cmake --build build && cd build && ctest --output-on-failure"]
