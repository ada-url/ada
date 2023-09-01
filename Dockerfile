FROM debian:12-slim@sha256:741bae561f5c2261f4cdd535e4fd4c248dec0aafc1b9a1410b3d67ad24571340

RUN apt-get update && apt-get install -y \
    apt-transport-https \
    gcc \
    clang \
    clang-tools \
    cmake

WORKDIR /repo

CMD ["bash", "-c", "cmake -B build && cmake --build build && cd build && ctest --output-on-failure"]
