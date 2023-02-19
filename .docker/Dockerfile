FROM rust:alpine3.16
WORKDIR /yk
COPY . /yk
RUN apk add make automake autoconf autoconf-archive libtool pkgconf g++ flex eudev-dev
ENV PCSC_LIB_DIR=/yk/vendored/pcsc-lite-1.9.9/out/lib
ENV PCSC_LIB_NAME='static=pcsclite'
RUN cd vendored && \
    tar -xvf pcsc-lite-1.9.9.tar.bz2 && \
    cd pcsc-lite-1.9.9 && \
    mkdir out && \
    ./bootstrap && \
    ./configure --enable-static --prefix=/yk/vendored/pcsc-lite-1.9.9/out --exec-prefix=/yk/vendored/pcsc-lite-1.9.9/out --disable-libsystemd --disable-libudev --disable-libusb && \
    make -j$(nproc) && \
    make install && \
    cd /yk && \
    chown -R 1000:1000 /yk

CMD ["cargo", "b", "--profile", "lto", "--target", "x86_64-unknown-linux-musl"]