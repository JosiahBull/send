FROM ghcr.io/josiahbull/dotfiles:latest
ARG USERNAME=user-name-goes-here
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME || true \
  && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
  && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
  && chmod 0440 /etc/sudoers.d/$USERNAME \
  && chsh -s /bin/zsh $USERNAME

# Install required packages.
# NOTE: no point filtering app lists, or using --no-install-recommends as
# this is a dev container and only expected to be built locally.
RUN apt-get update && apt-get install -y \
    curl \
    libssl-dev \
    pkg-config \
    libudev-dev \
    llvm \
    clang \
    gcc \
    cmake \
    libsqlite3-dev \
    zlib1g-dev \
    ca-certificates \
    git \
    nano \
    software-properties-common \
    musl-tools

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup toolchain install nightly

# TODO: move to base image.
RUN cargo install --locked sqlx-cli
RUN cargo install --locked cargo-insta

# Install docker + docker compose so we can start containers for testing inside of our devcontainer
RUN install -m 0755 -d /etc/apt/keyrings
RUN curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
RUN chmod a+r /etc/apt/keyrings/docker.asc
RUN echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
RUN apt-get update
RUN apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Install python tools.
RUN pip3 install thefuck
RUN pip3 install pre-commit

# Copy everything over from /root to /home/$USERNAME
RUN cp -r /root/. /home/$USERNAME
RUN chown -R $USERNAME:$USERNAME /home/$USERNAME

USER $USERNAME
