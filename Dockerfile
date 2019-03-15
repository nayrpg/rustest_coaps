FROM dockerhub.cisco.com/sto-docker-v2/c3m/ciscossl_base
RUN mkdir -p /usr/local/src/rust/ && \
    curl https://sh.rustup.rs -sSfo /usr/local/src/rust/install.sh && \
    chmod +x /usr/local/src/rust/install.sh && \
    /usr/local/src/rust/install.sh -y && \
    mkdir /root/rust/
ENV PATH=$PATH:/root/.cargo/bin \
    OPENSSL_DIR=${BASE_DIR}/ciscossl/${CISCOSSL_V_PATH}/linux/x86_64
WORKDIR /root/rust/
ENTRYPOINT ["cargo", "run"]