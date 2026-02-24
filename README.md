# Vayload Registry (Go)

Part of the Vayload ecosystem, this Go backend manages the lifecycle of Lua plugins. It handles plugin registration, versioning, publishing, uploads, and downloads, while supporting API keys for automated workflows and continuous deployment. Designed for flexibility, reliability, and scalability across multiple databases and storage backends.

Official site: [https://plugins.vayload.dev](https://plugins.vayload.dev)

## Features

- Full plugin lifecycle: create, update, publish, versioning
- Upload and download Lua plugin packages efficiently
- API keys for programmatic access and CI/CD integration
- Flexible storage: local disk and Cloudflare R2
- Database support: SQLite, Turso (libsql), PostgreSQL

## Tech Stack

Go, Fiber, sqlx, Zerolog, TOML configuration
