FROM ubuntu:18.04

ENV TZ=Europe/Berlin
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN mkdir -p /home/sip && \
    apt-get update -y && apt-get install -y unzip wget curl git libpython-dev python3 python3-pip python-pip ninja-build clang cmake radare2 libncurses5-dev && \
    apt-get upgrade -y --autoremove && \
    python3 -m pip install pip --upgrade && python3 -m pip install r2pipe matplotlib && \
    python -m pip install r2pipe pyelftools

WORKDIR /home/sip

# dynamoRIO is required for the tracer
RUN wget https://github.com/DynamoRIO/dynamorio/releases/download/release_8.0.0-1/DynamoRIO-Linux-8.0.0-1.tar.gz -O /home/sip/dynamorio.tar.gz && \
    cd /home/sip && tar xzf dynamorio.tar.gz && rm dynamorio.tar.gz

# dependencies for triton
RUN apt-get update && apt-get install -y libcapstone-dev libboost1.65-dev
RUN git clone --depth 1 -b z3-4.8.7 https://github.com/Z3Prover/z3.git && \
    cd z3 && python scripts/mk_make.py && cd build && make -j4 && make install
RUN git clone --depth 1 --recursive https://github.com/toizi/attacking_anti_tamper.git && \
    cd /home/sip/attacking_anti_tamper/tracer && ./build.sh Release && \
    cd /home/sip/attacking_anti_tamper/taint_cpp && ./build.sh Release

# libtinfo5 is a self-checksumming/closed_source dependency
# clang-6.0 is required to create compatible bitcode with self-checksumming/obfuscations
RUN git clone --depth 1 -b guard_obfuscation https://github.com/toizi/self-checksumming.git /home/sip/attacking_anti_tamper/self-checksumming && \
    mkdir -p /home/sip/attacking_anti_tamper/self-checksumming/build && \
    cd /home/sip/attacking_anti_tamper/self-checksumming/build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=/usr/lib/llvm-6.0/ .. && \
    cmake --build .

# Ghidra for forked self-checking since radare is not good enough at finding functions
RUN apt-get update && apt-get install -y unzip openjdk-11-jdk && \
    wget https://ghidra-sre.org/ghidra_9.0.4_PUBLIC_20190516.zip -O ghidra.zip && \
    unzip ghidra.zip && \
    rm ghidra.zip
ENV PATH="${PATH}:/home/sip/ghidra_9.0.4/support"

# obfuscation protections
# libtinfo5 and clang-6.0 are required for closed_source/opt and clang-6.0 for self-checksumming/obfuscations
RUN cd /home/sip/attacking_anti_tamper/self-checksumming && mkdir -p obfuscation && cd obfuscation && \
    git clone --depth 1 -b cfg_indirection https://github.com/toizi/Obfuscator-LLVM.git && \
    cd Obfuscator-LLVM && mkdir -p build && cd build && \
    cmake -G Ninja -DCMAKE_BUILD_TYPE=Release .. && \
    cmake --build . --target LLVMObfuscation && \
    cmake --build . --target clang && \
    cmake --build . --target opt

WORKDIR /home/sip/attacking_anti_tamper

CMD ["/bin/bash"]
