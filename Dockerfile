FROM debian:12-slim@sha256:d8f9d38c21495b04d1cca99805fbb383856e19794265684019bf193c3b7d67f9

RUN apt-get update && apt-get install -y \
    apt-transport-https \
    gcc \
    clang \
    clang-tools \
    cmake

WORKDIR /repo

CMD ["bash", "-c", "cmake -B build && cmake --build build && cd build && ctest --output-on-failure"]
