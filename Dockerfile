FROM debian:12-slim@sha256:67f3931ad8cb1967beec602d8c0506af1e37e8d73c2a0b38b181ec5d8560d395

RUN apt-get update && apt-get install -y \
    apt-transport-https \
    gcc \
    clang \
    clang-tools \
    cmake

WORKDIR /repo

CMD ["bash", "-c", "cmake -B build && cmake --build build && cd build && ctest --output-on-failure"]
