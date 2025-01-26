repo := 'ghcr.io/josiahbull/send'

# General SQLX files
codegen:
    @export DATABASE_URL=sqlite://$PWD/test.db
    @echo y | @sqlx database drop
    @sqlx database create
    @sqlx migrate run --source ./crates/database/migrations
    @sqlx prepare --workspace

# Run formatting
format:
    @cargo +nightly fmt
    @cargo autoinherit

# Run tests and check for unused dependencies
test:
    @cargo test
    @cargo +nightly udeps

# Update the insta snapshots
update-snapshots:
    @cargo insta test
    @cargo insta accept

# Build the project & Create dockerfiles for the desired triple
docker-build triple=(arch() + "-unknown-linux-musl"):
    #!/bin/bash

    set -o errexit -o nounset -o pipefail

    # Initalise docker buildx
    docker buildx create --use

    # If the 'cross' binary does not exist - install it.
    if ! command -v cross &> /dev/null; then
        echo "cross not found, installing it now"
        cargo install cross --locked --git https://github.com/cross-rs/cross
    fi

    # extract the arch from the triple
    arch=$(echo $triple | cut -d'-' -f1)
    platform="linux/$arch"

    # Set the target
    echo "Docker Version: $(docker --version)"
    echo "Docker buildx version: $(docker buildx version)"
    echo "target: $triple"
    echo "platform: $platform"
    echo "repo: {{repo}}"

    # Build the project
    CROSS_CONTAINER_IN_CONTAINER=true \
    cross build \
        --release \
        --target $triple

    # Copy the built file to ./target/tmp/server
    mkdir -p ./target/tmp
    rm -f ./target/tmp/server
    cp ./target/$triple/release/server ./target/tmp/server

    # Create the docker project
    docker buildx build \
        --platform $platform \
        --file ./Dockerfile \
        --tag "{{repo}}:$triple-$(git rev-parse --short HEAD)" \
        --tag "{{repo}}:$triple-latest" \
        --load \
        .

docker-push triple=(arch() + "-unknown-linux-musl"):
    #!/bin/bash

    set -o errexit -o nounset -o pipefail

    docker push {{repo}}:$triple-$(git rev-parse --short HEAD)
    docker push {{repo}}:$triple-latest

docker-manifest triples=(arch() + "-unknown-linux-musl"):
    #!/bin/bash

    set -o errexit -o nounset -o pipefail

    # Pull the images
    echo "Pulling images"
    for triple in {{triples}}; do
        echo "Pulling {{repo}}:$triple-$(git rev-parse --short HEAD)"
        docker pull {{repo}}:$triple-$(git rev-parse --short HEAD);
        docker pull {{repo}}:$triple-latest;
    done

    # Create the manifest for sha
    echo "Creating manifest for {{repo}}:$(git rev-parse --short HEAD)"
    docker manifest create {{repo}}:$(git rev-parse --short HEAD) \
        $(for triple in {{triples}}; do echo -n "--amend {{repo}}:$triple-$(git rev-parse --short HEAD) "; done)

    # Create the manifest for latest
    echo "Creating manifest for latest"
    docker manifest create {{repo}}:latest \
        $(for triple in {{triples}}; do echo -n "--amend {{repo}}:$triple-latest "; done)

docker-manifest-push:
    #!/bin/bash

    set -o errexit -o nounset -o pipefail

    docker manifest push "{{repo}}:$(git rev-parse --short HEAD)"
    docker manifest push "{{repo}}:latest"

default:
    @just --list
