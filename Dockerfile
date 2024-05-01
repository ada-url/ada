FROM debian:12-slim@sha256:155280b00ee0133250f7159b567a07d7cd03b1645714c3a7458b2287b0ca83cb

RUN apt-get update && apt-get install -y \
    apt-transport-https \
    gcc \
    clang \
    clang-tools \
    cmake

WORKDIR /repo

CMD ["bash", "-c", "cmake -B build && cmake --build build && cd build && ctest --output-on-failure"]
