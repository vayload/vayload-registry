PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA temp_store = MEMORY;
PRAGMA busy_timeout = 5000;

-- ================================
-- DROP TABLES
-- ================================
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS plugin_tasks;
DROP TABLE IF EXISTS plugin_versions;
DROP TABLE IF EXISTS plugins;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS plugin_reviews;
DROP TABLE IF EXISTS plugin_dependencies;
DROP TABLE IF EXISTS plugin_collaborators;
DROP TABLE IF EXISTS plugin_stats;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS storage_objects;

-- ================================
-- USERS
-- ================================
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    email TEXT UNIQUE,
    password_hash TEXT,
    avatar_url TEXT,
    provider TEXT NOT NULL DEFAULT 'password'
        CHECK(provider IN ('password','github','google','other')),
    provider_id TEXT,
    is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0,1)),
    role TEXT NOT NULL DEFAULT 'developer'
        CHECK(role IN ('admin','developer','moderator')),
    verification_token TEXT,
    verified_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_login_at INTEGER
);

CREATE INDEX idx_users_provider 
ON users(provider, provider_id);

-- ================================
-- REFRESH TOKENS
-- ================================
CREATE TABLE refresh_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL,
    family_id TEXT NOT NULL,
    parent_id TEXT,
    used_at INTEGER,
    revoked_at INTEGER,
    revoked_reason TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    user_agent TEXT,
    ip_address TEXT,

    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(parent_id) REFERENCES refresh_tokens(id) ON DELETE SET NULL
);

CREATE INDEX idx_refresh_tokens_family 
ON refresh_tokens(family_id);

CREATE INDEX idx_refresh_tokens_user_active 
ON refresh_tokens(user_id, revoked_at, expires_at);

-- ================================
-- PLUGINS
-- ================================
CREATE TABLE plugins (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    description TEXT,
    homepage_url TEXT,
    repo_url TEXT,
    documentation_url TEXT,
    visibility TEXT NOT NULL DEFAULT 'public'
        CHECK(visibility IN ('public','private','unlisted')),
    tags TEXT CHECK(tags IS NULL OR json_valid(tags)),
    status TEXT NOT NULL DEFAULT 'draft'
        CHECK(status IN ('draft','published','deprecated','archived','yanked')),
    pricing_type TEXT NOT NULL DEFAULT 'free'
        CHECK(pricing_type IN ('free','paid','subscription','not_applicable')),
    total_downloads INTEGER NOT NULL DEFAULT 0,
    latest_stable_version TEXT,
    latest_beta_version TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    deleted_at INTEGER,

    UNIQUE(namespace, name),

    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_plugins_owner ON plugins(owner_id);

CREATE INDEX idx_plugins_public_discovery
ON plugins(status, visibility, total_downloads DESC);

CREATE INDEX idx_plugins_public_only
ON plugins(total_downloads DESC)
WHERE visibility='public' AND deleted_at IS NULL;

-- ================================
-- STORAGE OBJECTS
-- ================================
CREATE TABLE storage_objects (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    mime_type TEXT NOT NULL,
    blob BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_storage_objects_type 
ON storage_objects(type);

-- ================================
-- PLUGIN VERSIONS
-- ================================
CREATE TABLE plugin_versions (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    version TEXT NOT NULL,
    published_at INTEGER NOT NULL DEFAULT (unixepoch()),
    yanked INTEGER NOT NULL DEFAULT 0 CHECK(yanked IN (0,1)),
    yank_reason TEXT,
    status TEXT NOT NULL DEFAULT 'stable'
        CHECK(status IN ('draft','beta','stable','deprecated')),

    manifest_object TEXT NOT NULL,
    readme_object TEXT,
    license_object TEXT,
    license_type TEXT,

    integrity BLOB NOT NULL,
    filename TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    total_files INTEGER NOT NULL,

    downloads_count INTEGER NOT NULL DEFAULT 0,
    changelog TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),

    UNIQUE(plugin_id, version),

    FOREIGN KEY(plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    FOREIGN KEY(manifest_object) REFERENCES storage_objects(id),
    FOREIGN KEY(readme_object) REFERENCES storage_objects(id),
    FOREIGN KEY(license_object) REFERENCES storage_objects(id)
);

CREATE INDEX idx_plugin_versions_lookup
ON plugin_versions(plugin_id, status, yanked, published_at DESC);

-- ================================
-- PLUGIN TASKS
-- ================================
CREATE TABLE plugin_tasks (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    version TEXT NOT NULL,
    user_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','processing','completed','failed')),
    metadata TEXT NOT NULL CHECK(json_valid(metadata)),
    error TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),

    FOREIGN KEY(plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX idx_plugin_tasks_status_created
ON plugin_tasks(status, created_at);

CREATE INDEX idx_plugin_tasks_plugin_status
ON plugin_tasks(plugin_id, status);

-- ================================
-- API TOKENS
-- ================================
CREATE TABLE api_tokens (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    plugin_id TEXT,
    key_mask TEXT NOT NULL,
    name TEXT NOT NULL,
    scope TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_used_at INTEGER,
    expires_at INTEGER,
    revoked_at INTEGER,
    revoked_reason TEXT,

    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(plugin_id) REFERENCES plugins(id) ON DELETE CASCADE
);

CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);

-- ================================
-- PLUGIN DEPENDENCIES
-- ================================
CREATE TABLE plugin_dependencies (
    id TEXT PRIMARY KEY,
    plugin_version_id TEXT NOT NULL,
    dependency_name TEXT NOT NULL,
    version_requirement TEXT NOT NULL,
    is_optional INTEGER NOT NULL DEFAULT 0 CHECK(is_optional IN (0,1)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),

    FOREIGN KEY(plugin_version_id)
        REFERENCES plugin_versions(id) ON DELETE CASCADE
);

CREATE INDEX idx_plugin_deps_version
ON plugin_dependencies(plugin_version_id);

-- ================================
-- PLUGIN STATS
-- ================================
CREATE TABLE plugin_stats (
    plugin_id TEXT NOT NULL,
    stat_date TEXT NOT NULL,
    downloads_count INTEGER NOT NULL DEFAULT 0,
    views_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY(plugin_id, stat_date),
    FOREIGN KEY(plugin_id) REFERENCES plugins(id) ON DELETE CASCADE
);

CREATE INDEX idx_plugin_stats_recent
ON plugin_stats(plugin_id, stat_date DESC);

-- ================================
-- REVIEWS
-- ================================
CREATE TABLE plugin_reviews (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    title TEXT,
    comment TEXT,
    version TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch()),

    UNIQUE(plugin_id, user_id),

    FOREIGN KEY(plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX idx_reviews_plugin
ON plugin_reviews(plugin_id);

-- ================================
-- COLLABORATORS
-- ================================
CREATE TABLE plugin_collaborators (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'contributor'
        CHECK(role IN ('owner','maintainer','contributor','viewer')),
    added_at INTEGER NOT NULL DEFAULT (unixepoch()),
    added_by TEXT NOT NULL,

    UNIQUE(plugin_id, user_id),

    FOREIGN KEY(plugin_id) REFERENCES plugins(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(added_by) REFERENCES users(id)
);

-- ================================
-- AUDIT LOGS
-- ================================
CREATE TABLE audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    metadata TEXT CHECK(metadata IS NULL OR json_valid(metadata)),
    ip_address TEXT,
    user_agent TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_audit_user_time
ON audit_logs(user_id, created_at DESC);

CREATE INDEX idx_audit_resource
ON audit_logs(resource_type, resource_id);