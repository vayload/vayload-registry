
-- DROP ALL TABLES
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS plugin_tasks;
DROP TABLE IF EXISTS plugins;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS plugin_versions;
DROP TABLE IF EXISTS plugin_reviews;
DROP TABLE IF EXISTS plugin_dependencies;
DROP TABLE IF EXISTS plugin_collaborators;
DROP TABLE IF EXISTS audit_logs;

PRAGMA foreign_keys = ON;


CREATE TABLE IF NOT EXISTS users (
    id          TEXT PRIMARY KEY,               -- ULID 26 chars
    username    TEXT NOT NULL UNIQUE,
    email       TEXT UNIQUE,
    password_hash TEXT,
    avatar_url  TEXT,
    provider    TEXT NOT NULL DEFAULT 'password' CHECK(provider IN ('password', 'github', 'google', 'other')),
    provider_id TEXT,
    is_active   INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    role        TEXT NOT NULL DEFAULT 'developer' CHECK(role IN ('admin', 'developer', 'moderator')),
    verification_token TEXT,
    verified_at DATETIME DEFAULT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at DATETIME
);

CREATE INDEX idx_users_email        ON users(email);
CREATE INDEX idx_users_provider     ON users(provider, provider_id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    family_id TEXT NOT NULL,
    parent_id TEXT DEFAULT NULL,
    used_at DATETIME DEFAULT NULL,
    revoked_at DATETIME DEFAULT NULL,
    revoked_reason TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_agent TEXT,
    ip_address TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(parent_id) REFERENCES refresh_tokens(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS plugin_tasks (
    id              TEXT PRIMARY KEY,
    plugin_id       TEXT NOT NULL,
    version         TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'processing', 'completed', 'failed')),
    metadata        TEXT NOT NULL, -- json string of PluginManifest
    error           TEXT,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Plugins
CREATE TABLE IF NOT EXISTS plugins (
    id              TEXT PRIMARY KEY,
    owner_id        TEXT NOT NULL,
    name            TEXT NOT NULL UNIQUE,
    namespace       TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    description     TEXT,
    homepage_url    TEXT, -- url of homepage_url or github repository url
    repo_url        TEXT, -- repository url if is provided
    documentation_url TEXT, -- url of documentation_url or github repository url
    visibility      TEXT NOT NULL DEFAULT 'public' CHECK(visibility IN ('public', 'private', 'unlisted')),
    tags            TEXT,                       -- JSON array string
    status          TEXT NOT NULL DEFAULT 'draft'
        CHECK(status IN ('draft', 'published', 'deprecated', 'archived', 'yanked')),
    pricing_type    TEXT NOT NULL DEFAULT 'free' CHECK(pricing_type IN ('free', 'paid', 'subscription', 'not_applicable')),
    total_downloads INTEGER NOT NULL DEFAULT 0,

	-- Fast discovery versions
    latest_stable_version TEXT,
    latest_beta_version TEXT,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at      DATETIME,

    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_plugins_owner ON plugins(owner_id);
CREATE INDEX idx_plugins_name ON plugins(name);
CREATE INDEX idx_plugins_display_name ON plugins(display_name);
CREATE INDEX idx_plugins_latest_stable_version ON plugins(latest_stable_version);
CREATE INDEX idx_plugins_latest_beta_version ON plugins(latest_beta_version);

CREATE TABLE IF NOT EXISTS storage_objects (
	id TEXT PRIMARY KEY,          -- SHA256 hash
	type TEXT NOT NULL,           -- 'tarball', 'manifest', 'readme', 'license', etc.
	size_bytes INTEGER NOT NULL,
	mime_type TEXT NOT NULL,      -- 'application/json', 'text/markdown', 'application/gzip'
	blob BLOB NOT NULL,
	created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_storage_objects_type ON storage_objects(type);

CREATE TABLE IF NOT EXISTS plugin_versions (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    version TEXT NOT NULL,
    published_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    yanked INTEGER NOT NULL DEFAULT 0 CHECK(yanked IN (0,1)),
    yank_reason TEXT,
    status TEXT NOT NULL DEFAULT 'stable'  CHECK(status IN ('draft', 'beta', 'stable', 'deprecated')),

    -- Blobs files
    manifest_object TEXT NOT NULL,  -- hash SHA256
    readme_object TEXT,             -- hash SHA256
    license_object TEXT,            -- hash SHA256
    license_type TEXT,              -- MIT, GPL-3.0, etc.

    integrity BLOB NOT NULL,        -- SHA256 checksum
    filename TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    total_files INTEGER NOT NULL,

    downloads_count INTEGER NOT NULL DEFAULT 0,
    changelog TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (plugin_id, version),

    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    FOREIGN KEY (manifest_object) REFERENCES storage_objects(id),
    FOREIGN KEY (readme_object) REFERENCES storage_objects(id),
    FOREIGN KEY (license_object) REFERENCES storage_objects(id)
);

CREATE INDEX idx_plugin_versions_plugin ON plugin_versions(plugin_id);
CREATE INDEX idx_plugin_versions_yanked ON plugin_versions(plugin_id, yanked);


CREATE TABLE IF NOT EXISTS api_tokens (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,            -- key hash SHA256
    plugin_id   TEXT NULL CHECK (
        (plugin_id IS NULL AND scope = 'global')
        OR
        (plugin_id IS NOT NULL AND scope != 'global')
    ),
    key_mask    TEXT NOT NULL,                   -- mask like vk_dsgsdg*****jifomfr
    name        TEXT NOT NULL,
    scope       TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    expires_at  DATETIME,
    revoked_at  DATETIME,
    revoked_reason TEXT,

    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE
);

CREATE INDEX idx_api_tokens_user     ON api_tokens(user_id);
CREATE INDEX idx_api_tokens_hash     ON api_tokens(key_hash);
CREATE INDEX idx_api_tokens_mask     ON api_tokens(key_mask);


CREATE TABLE IF NOT EXISTS plugin_dependencies (
    id                  TEXT PRIMARY KEY,
    plugin_version_id   TEXT NOT NULL,
    dependency_name     TEXT NOT NULL,
    version_requirement TEXT NOT NULL,
    is_optional         INTEGER NOT NULL DEFAULT 0 CHECK(is_optional IN (0,1)),
    created_at          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (plugin_version_id) REFERENCES plugin_versions(id) ON DELETE CASCADE
);

CREATE INDEX idx_plugin_deps_version ON plugin_dependencies(plugin_version_id);


CREATE TABLE plugin_stats (
    plugin_id   TEXT NOT NULL,
    stat_date   DATE NOT NULL,
    downloads_count INTEGER NOT NULL DEFAULT 0,
    views_count     INTEGER NOT NULL DEFAULT 0,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (plugin_id, stat_date),
    FOREIGN KEY (plugin_id)
        REFERENCES plugins(id)
        ON DELETE CASCADE
);

CREATE INDEX idx_plugin_stats_date ON plugin_stats(stat_date);

CREATE TABLE IF NOT EXISTS plugin_reviews (
    id          TEXT PRIMARY KEY,
    plugin_id   TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    rating      INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    title       TEXT,
    comment     TEXT,
    version     TEXT,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (plugin_id, user_id),
    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)    REFERENCES users(id)    ON DELETE RESTRICT
);

CREATE INDEX idx_reviews_plugin ON plugin_reviews(plugin_id);
CREATE INDEX idx_reviews_user   ON plugin_reviews(user_id);


CREATE TABLE IF NOT EXISTS plugin_collaborators (
    id          TEXT PRIMARY KEY,
    plugin_id   TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'contributor'
        CHECK(role IN ('owner', 'maintainer', 'contributor', 'viewer')),
    added_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    added_by    TEXT NOT NULL REFERENCES users(id),

    UNIQUE (plugin_id, user_id),
    FOREIGN KEY (plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)   REFERENCES users(id)   ON DELETE CASCADE,
    FOREIGN KEY (added_by)  REFERENCES users(id)
);


CREATE TABLE IF NOT EXISTS audit_logs (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    metadata        TEXT,                           -- JSON
    ip_address      TEXT,
    user_agent      TEXT,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_user_time  ON audit_logs(user_id, created_at);
CREATE INDEX idx_audit_resource   ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_created    ON audit_logs(created_at);
