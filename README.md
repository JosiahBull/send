# Send

A file transfer tool for sharing files over the internet.

## One-time use to send a file

```bash
curl https://raw.githubusercontent.com/JosiahBull/send/main/scripts/upload.sh | bash -s -- --key ~/.ssh/id_ed25519 -f <file>
```

## Permanent installation

```bash
curl https://raw.githubusercontent.com/JosiahBull/send/main/scripts/upload.sh | bash -s -- --install
```

## Running the binary

```bash
git clone https://github.com/josiahbull/send
cd send
cp .example.env .env
# nano .env, vi .env, or vim .env
# and add your configuration

docker compose up -d --env-file .env
```

## Contribution

If you would like to contribute to this project, please open an issue or a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
