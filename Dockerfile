FROM debian:11-slim

RUN apt-get update && apt-get install -y \
    apt-transport-https \
    gcc \
    clang \
    clang-tools \
    cmake

WORKDIR /repo

CMD ["bash", "-c", "cmake -B build && cmake --build build && cd build && ctest --output-on-failure"]
