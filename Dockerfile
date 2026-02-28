ARG BASE_IMAGE=ubuntu:26.04

FROM $BASE_IMAGE AS unity-editor

RUN apt-get update && apt-get --no-install-recommends install -y ca-certificates make curl xz-utils binutils

WORKDIR /home/ubuntu

ARG UNITY_VERSION
RUN \
    --mount=type=bind,src=./unity/common.mk,dst=./unity/common.mk \
    --mount=type=bind,src=./unity/editor.mk,dst=./unity/editor.mk \
    --mount=type=bind,src=./unity/$UNITY_VERSION/editor.mk,dst=./unity/$UNITY_VERSION/editor.mk \
    make -C unity/$UNITY_VERSION -f editor.mk editor

FROM $BASE_IMAGE AS build-host

# libc6:i386 and g++ are only needed for 5.3.5f1...
RUN dpkg --add-architecture i386 && apt-get update && apt-get --no-install-recommends install -y make clang libc6:i386 g++

USER ubuntu
WORKDIR /home/ubuntu

ARG UNITY_VERSION
RUN \
    --mount=type=bind,rw,from=unity-editor,src=/home/ubuntu/unity,dst=./unity \
    --mount=type=bind,src=./unity/common.mk,dst=./unity/common.mk \
    --mount=type=bind,src=./unity/build.mk,dst=./unity/build.mk \
    --mount=type=bind,src=./unity/$UNITY_VERSION/build.mk,dst=./unity/$UNITY_VERSION/build.mk \
    --mount=type=bind,src=./test/GameAssembly.cs,dst=./test/GameAssembly.cs \
    make -C unity/$UNITY_VERSION -f build.mk assembly

RUN \
    --mount=type=bind,src=./test/host.c,target=./test/host.c \
    clang -o build/host ./test/host.c

FROM $BASE_IMAGE AS final

RUN apt-get update && apt-get --no-install-recommends install -y xz-utils

WORKDIR /bin

ARG FRIDA_VERSION=17.7.3
ADD https://github.com/frida/frida/releases/download/$FRIDA_VERSION/frida-server-$FRIDA_VERSION-linux-x86_64.xz .
RUN <<EOF
xz -d frida-server-*.xz
mv frida-server-* frida-server
chmod +x frida-server
EOF

CMD [ "frida-server", "-l", "0.0.0.0:27042" ]
EXPOSE 27042

WORKDIR /home/ubuntu

COPY --from=build-host --parents /home/ubuntu/build/*/out /home/ubuntu/build/host /
