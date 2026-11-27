# AetherFlow shared helpers: safe_config_python, DB backup/restore, Servarr TOML, and archive staging.
# Sourced by packages/common.sh; do not execute directly.

safe_config_python() (
    local argument_index=0 argument
    export AF_CONFIG_ARGUMENT_COUNT="$#"
    for argument in "$@"; do
        export "AF_CONFIG_ARGUMENT_${argument_index}=$argument"
        argument_index=$((argument_index + 1))
    done
    {
        cat <<'PYHELPER'
import contextlib, os, pathlib, secrets, stat, sys
sys.argv = ['-'] + [os.environ.pop(f'AF_CONFIG_ARGUMENT_{index}') for index in range(int(os.environ.pop('AF_CONFIG_ARGUMENT_COUNT')))]

def config_directory(filename, create=True):
    path = pathlib.PurePath(filename)
    if not path.is_absolute() or '..' in path.parts or not path.name:
        raise ValueError('Invalid managed configuration path')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o750, dir_fd=directory)
                except FileExistsError:
                    pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory, path.name
    except BaseException:
        os.close(directory)
        raise

class ManagedConfig:
    def __init__(self, filename, create_parents=True):
        self.directory, self.name = config_directory(filename, create_parents)
        self.descriptor = None
        self.metadata = None
        try:
            try:
                self.descriptor = os.open(self.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=self.directory)
            except FileNotFoundError:
                pass
            else:
                self.metadata = os.fstat(self.descriptor)
                self.validate(self.metadata)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def validate(metadata):
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError('Managed configuration must be a single-link regular file')

    def check_target(self):
        try:
            current = os.stat(self.name, dir_fd=self.directory, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None:
            self.validate(current)
        if (current is None) != (self.metadata is None):
            raise ValueError('Managed configuration target changed')
        if current is not None and (current.st_dev, current.st_ino) != (self.metadata.st_dev, self.metadata.st_ino):
            raise ValueError('Managed configuration target changed')

    def read_bytes(self, max_bytes=None):
        if self.descriptor is None:
            return b''
        metadata = os.fstat(self.descriptor)
        self.validate(metadata)
        if max_bytes is not None and metadata.st_size > max_bytes:
            raise ValueError('Managed configuration exceeds maximum allowed size')
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(self.descriptor), 'rb') as source:
            data = source.read() if max_bytes is None else source.read(max_bytes + 1)
        if max_bytes is not None and len(data) > max_bytes:
            raise ValueError('Managed configuration exceeds maximum allowed size')
        return data

    def read_text(self, max_bytes=None):
        return self.read_bytes(max_bytes=max_bytes).decode('utf-8')

    def write_text(self, text, mode=None):
        self.check_target()
        temporary = '.af-config.' + secrets.token_hex(12)
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
                if self.metadata:
                    os.fchown(output.fileno(), self.metadata.st_uid, self.metadata.st_gid)
                os.fchmod(output.fileno(), mode if mode is not None else (stat.S_IMODE(self.metadata.st_mode) if self.metadata else 0o640))
                output.write(text)
                output.flush()
                os.fsync(output.fileno())
                metadata = os.fstat(output.fileno())
            self.check_target()
            os.replace(temporary, self.name, src_dir_fd=self.directory, dst_dir_fd=self.directory)
            self.metadata = metadata
            os.fsync(self.directory)
            if self.descriptor is not None:
                os.close(self.descriptor)
                self.descriptor = None
            self.descriptor = os.open(self.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=self.directory)
            self.validate(os.fstat(self.descriptor))
            self.check_target()
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self.directory)

    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor)
        os.close(self.directory)

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.close()

def safe_read_text(filename, max_bytes=None):
    with ManagedConfig(filename) as config:
        return config.read_text(max_bytes=max_bytes)

def safe_write_text(filename, text, mode=None):
    with ManagedConfig(filename) as config:
        config.write_text(text, mode)

PYHELPER
        cat
    } | python3 -
)

read_navidrome_database_path() {
    validate_config_paths "$1" || return 1
    safe_config_python "$1" <<'PYEOF'
import posixpath, sys
try:
    import tomllib
except ModuleNotFoundError:
    import toml as tomllib
try:
    config = tomllib.loads(safe_read_text(sys.argv[1]))
except FileNotFoundError:
    config = {}
folders = [value for key, value in config.items() if key.lower() == 'datafolder']
if len(folders) > 1:
    raise ValueError('Ambiguous Navidrome DataFolder')
folder = folders[0] if folders else '/var/lib/navidrome'
if not isinstance(folder, str) or not folder.strip() or any(character in folder for character in '\r\n\0'):
    raise ValueError('Invalid Navidrome DataFolder')
if not posixpath.isabs(folder):
    folder = posixpath.join('/var/lib/navidrome', folder)
print(posixpath.join(posixpath.normpath(folder), 'navidrome.db'))
PYEOF
}

read_app_database_config() {
    validate_config_paths "$2" || return 1
    safe_config_python "$@" <<'PYEOF'
import configparser, re, sys
app, filename = sys.argv[1:]
raw = safe_read_text(filename)
if app == 'nextcloud':
    strings_or_comments = r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"|/\*.*?\*/|//[^\n]*|\#[^\n]*"
    raw = re.sub(strings_or_comments, lambda match: match.group(0) if match.group(1) is not None or match.group(2) is not None else ' ', raw, flags=re.S)
    structure = re.sub(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"", "''", raw)
    variables = re.findall(r'\$[A-Za-z_][A-Za-z0-9_]*', structure)
    if (variables and variables != ['$CONFIG'] or re.search(r'\b(?:require|require_once|include|include_once|eval)\b', structure)
            or re.search(r'\b(?!array\b)[A-Za-z_][A-Za-z0-9_]*\s*\(', structure, re.I)
            or variables and not re.search(r'\$CONFIG\s*=\s*(?:array\s*\(|\[)', structure)):
        raise ValueError('Dynamic Nextcloud database configuration cannot be backed up safely')
    tokens = re.findall(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|\$[A-Za-z_][A-Za-z0-9_]*|=>|[A-Za-z_][A-Za-z0-9_]*|[+-]?[0-9]+(?:\.[0-9]+)?|[^\s]", raw)
    def parse_literal(position):
        token = tokens[position]
        if token == '[' or token.lower() == 'array':
            closing = ']' if token == '[' else ')'
            if token != '[' and tokens[position + 1] != '(':
                raise ValueError('Invalid Nextcloud configuration array')
            position += 1 if token == '[' else 2
            result, next_index = {}, 0
            while tokens[position] != closing:
                entry, position = parse_literal(position)
                if tokens[position] == '=>':
                    key = entry
                    entry, position = parse_literal(position + 1)
                else:
                    key = next_index
                if not isinstance(key, (str, int)) or key in result:
                    raise ValueError('Ambiguous Nextcloud configuration key')
                result[key] = entry
                if isinstance(key, int):
                    next_index = max(next_index, key + 1)
                if tokens[position] == ',':
                    position += 1
                elif tokens[position] != closing:
                    raise ValueError('Nextcloud configuration must contain only literal values')
            return result, position + 1
        if token.startswith(("'", '"')):
            text = token[1:-1]
            if token.startswith("'"):
                return text.replace("\\'", "'").replace('\\\\', '\\'), position + 1
            decoded, offset = [], 0
            escapes = {'n': '\n', 'r': '\r', 't': '\t', 'v': '\v', 'e': '\x1b', 'f': '\f',
                       '$': '$', '"': '"', '\\': '\\'}
            while offset < len(text):
                character = text[offset]
                if character == '$':
                    raise ValueError('Unsupported interpolated Nextcloud setting')
                if character == '\\':
                    offset += 1
                    character = text[offset]
                    numeric = re.match(r'x([0-9A-Fa-f]{1,2})|([0-7]{1,3})|u\{([0-9A-Fa-f]+)\}', text[offset:])
                    if numeric:
                        codepoint = int(next(group for group in numeric.groups() if group is not None),
                                        8 if numeric.group(2) else 16)
                        character = chr(codepoint & 255 if numeric.group(2) else codepoint)
                        offset += len(numeric.group(0)) - 1
                    else:
                        character = escapes.get(character, '\\' + character)
                decoded.append(character)
                offset += 1
            return ''.join(decoded), position + 1
        if token.lower() in ('true', 'false', 'null'):
            return {'true': True, 'false': False, 'null': None}[token.lower()], position + 1
        if re.fullmatch(r'[+-]?[0-9]+(?:\.[0-9]+)?', token):
            return float(token) if '.' in token else int(token), position + 1
        raise ValueError('Nextcloud configuration must contain only literal values')
    config = {}
    if variables:
        position = tokens.index('$CONFIG')
        config, position = parse_literal(position + 2)
        if not isinstance(config, dict) or tokens[position:] not in ([], [';'], [';', '?', '>'], ['?', '>']):
            raise ValueError('Dynamic Nextcloud configuration cannot be backed up safely')
    def value(key, default=''):
        text = config.get(key, default)
        if not isinstance(text, str):
            raise ValueError('Database settings must be literal strings: ' + key)
        return text
    values = [value('dbtype', 'mysql'), value('dbname', 'nextcloud'), value('dbhost', 'localhost'),
              value('dbuser'), value('dbpassword'), value('datadirectory', '/var/www/nextcloud/data')]
else:
    config = configparser.ConfigParser(interpolation=None)
    config.read_string('[DEFAULT]\n' + raw)
    database = config['database'] if config.has_section('database') else {}
    def value(key, default=''):
        text = database.get(key, default).strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'", '`'):
            text = text[1:-1]
        return text
    values = [value('DB_TYPE', 'sqlite3'), value('NAME', 'gitea'), value('HOST'), value('USER'),
              value('PASSWD'), value('PATH', '/var/lib/gitea/data/gitea.db')]
values[0] = values[0].lower()
if values[0] not in ('mysql', 'mariadb', 'postgres', 'pgsql', 'sqlite', 'sqlite3'):
    raise ValueError('Unsupported retained database backend')
if not re.fullmatch(r'[A-Za-z0-9_]+', values[1]):
    raise ValueError('Unsafe retained database name')
if any(any(character in text for character in '\r\n\0') for text in values):
    raise ValueError('Invalid multiline database setting')
print('\n'.join(values))
PYEOF
}

nextcloud_database_ownership() (
    safe_config_python "$@" <<'PYEOF'
import hashlib, json, re, sys
operation, filename, backend, database, host, username, password, data_directory = sys.argv[1:]
if operation not in ('create', 'verify'):
    raise ValueError('Unsupported Nextcloud database ownership operation')
if backend != 'mysql' or host != 'localhost':
    raise ValueError('Automatic purge requires an installer-provisioned local MySQL database')
if not re.fullmatch(r'[A-Za-z0-9_]+', database) or not re.fullmatch(r'[A-Za-z0-9_]+', username):
    raise ValueError('Unsafe Nextcloud database identity')
expected = {
    'format': 1, 'application': 'nextcloud', 'backend': backend,
    'database': database, 'host': host, 'username': username,
    'password_sha256': hashlib.sha256(password.encode('utf-8')).hexdigest(),
    'data_directory': data_directory,
}
with ManagedConfig(filename, create_parents=False) as config:
    directory = os.fstat(config.directory)
    if directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) & 0o022:
        raise ValueError('Nextcloud database ownership directory is not trusted')
    if operation == 'create':
        if config.metadata is not None:
            raise ValueError('Refusing to replace existing Nextcloud database ownership')
        config.write_text(json.dumps(expected, sort_keys=True) + '\n', 0o600)
    else:
        if config.metadata is None:
            raise ValueError('Nextcloud database ownership is unproven; configuration retained for operator cleanup')
        if config.metadata.st_uid != os.geteuid() or stat.S_IMODE(config.metadata.st_mode) & 0o077:
            raise ValueError('Nextcloud database ownership file is not trusted')
        if json.loads(config.read_text()) != expected:
            raise ValueError('Configured Nextcloud database does not match installer ownership; purge refused')
PYEOF
)

configured_database_connection() {
    local backend="$1" host="$2" username="$3" port=""
    AF_DATABASE_ARGS=()
    if [[ "$host" =~ ^\[([a-fA-F0-9:]+)\](:([0-9]+))?$ ]]; then
        host="${BASH_REMATCH[1]}" port="${BASH_REMATCH[3]}"
    elif [[ "$host" =~ ^([A-Za-z0-9_.-]+):([0-9]+)$ ]]; then
        host="${BASH_REMATCH[1]}" port="${BASH_REMATCH[2]}"
    elif [[ -n "$host" && ! "$host" =~ ^[A-Za-z0-9_./:-]+$ ]]; then
        print_error "Unsupported retained database host"
        return 1
    fi
    [[ -z "$host" ]] || AF_DATABASE_ARGS+=("--host=$host")
    if [[ -n "$port" ]]; then
        (( 10#$port > 0 && 10#$port <= 65535 )) || return 1
        AF_DATABASE_ARGS+=("--port=$port")
    fi
    if [[ -n "$username" ]]; then
        if [[ "$backend" == mysql || "$backend" == mariadb ]]; then
            AF_DATABASE_ARGS+=("--user=$username")
        else
            AF_DATABASE_ARGS+=("--username=$username")
        fi
    fi
}

configured_postgresql_cleanup() {
    cat <<'SQL'
SET LOCAL lock_timeout = '5s';
SET LOCAL search_path = pg_catalog;
DO $af_cleanup$
DECLARE
    entry record;
    recipient text;
    object_kind text;
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = current_database()
                   AND datdba = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery requires the database owner';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_event_trigger)
       OR EXISTS (SELECT FROM pg_catalog.pg_subscription)
       OR EXISTS (SELECT FROM pg_catalog.pg_publication)
       OR EXISTS (SELECT FROM pg_catalog.pg_foreign_data_wrapper)
       OR EXISTS (SELECT FROM pg_catalog.pg_foreign_server)
       OR EXISTS (SELECT FROM pg_catalog.pg_language WHERE lanname NOT IN ('internal', 'c', 'sql', 'plpgsql'))
       OR EXISTS (SELECT FROM pg_catalog.pg_shseclabel WHERE classoid = 'pg_catalog.pg_database'::regclass
                  AND objoid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery cannot safely reconstruct database-wide replication, event triggers, foreign servers, languages or security labels';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql'
               AND (extowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
                    OR extconfig IS NOT NULL)) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery requires application-owned extensions without configuration tables';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_class WHERE oid >= 16384 AND relnamespace IN
               (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema')))
       OR EXISTS (SELECT FROM pg_catalog.pg_proc WHERE oid >= 16384 AND pronamespace IN
                  (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema')))
       OR EXISTS (SELECT FROM pg_catalog.pg_type WHERE oid >= 16384 AND typnamespace IN
                  (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema'))) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery cannot reconstruct application objects in system schemas';
    END IF;
    FOR entry IN SELECT extname FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql' LOOP
        EXECUTE format('DROP EXTENSION %I CASCADE', entry.extname);
    END LOOP;
    FOR entry IN SELECT castsource::regtype AS source_type, casttarget::regtype AS target_type
                 FROM pg_catalog.pg_cast WHERE oid >= 16384 LOOP
        EXECUTE format('DROP CAST (%s AS %s) CASCADE', entry.source_type, entry.target_type);
    END LOOP;
    FOR entry IN SELECT nspname FROM pg_catalog.pg_namespace
                 WHERE nspname <> 'information_schema' AND nspname !~ '^pg_' LOOP
        EXECUTE format('DROP SCHEMA %I CASCADE', entry.nspname);
    END LOOP;
    PERFORM pg_catalog.lo_unlink(oid) FROM pg_catalog.pg_largeobject_metadata;
    FOR entry IN SELECT DISTINCT defaults.defaclrole, defaults.defaclobjtype, permissions.grantee
                 FROM pg_catalog.pg_default_acl AS defaults
                 CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS permissions
                 WHERE defaults.defaclnamespace = 0 LOOP
        object_kind := CASE entry.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES'
                       WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' WHEN 'n' THEN 'SCHEMAS' END;
        IF object_kind IS NULL THEN
            RAISE EXCEPTION 'Unsupported PostgreSQL default privilege object kind';
        END IF;
        recipient := CASE WHEN entry.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(entry.grantee)) END;
        EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL ON %s FROM %s CASCADE',
                       pg_catalog.pg_get_userbyid(entry.defaclrole), object_kind, recipient);
    END LOOP;
    FOR entry IN SELECT DISTINCT defaclrole, defaclobjtype FROM pg_catalog.pg_default_acl
                 WHERE defaclnamespace = 0 LOOP
        object_kind := CASE entry.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES'
                       WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' WHEN 'n' THEN 'SCHEMAS' END;
        EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I GRANT ALL ON %s TO %I',
                       pg_catalog.pg_get_userbyid(entry.defaclrole), object_kind, pg_catalog.pg_get_userbyid(entry.defaclrole));
        IF entry.defaclobjtype IN ('f', 'T') THEN
            EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I GRANT %s ON %s TO PUBLIC',
                           pg_catalog.pg_get_userbyid(entry.defaclrole),
                           CASE entry.defaclobjtype WHEN 'f' THEN 'EXECUTE' ELSE 'USAGE' END, object_kind);
        END IF;
    END LOOP;
END
$af_cleanup$;
SQL
}

backup_configured_database() (
    local backup="$1" backend="$2" database="$3" host="$4" username="$5" password="$6" sqlite_path="$7"
    umask 077
    [[ "$database" =~ ^[A-Za-z0-9_]+$ && "$backup" == /* && "$backup" != / && ! -L "$backup" ]] || return 1
    validate_config_paths "$backup/.af-database-ready" || return 1
    mkdir -m 0700 -- "$backup" || return 1
    case "$backend" in
        mysql|mariadb)
            configured_database_connection "$backend" "$host" "$username" || return 1
            MYSQL_PWD="$password" mysqldump "${AF_DATABASE_ARGS[@]}" --single-transaction --add-drop-database --databases "$database" > "$backup/database.sql" || return 1
            [[ -s "$backup/database.sql" ]] || return 1
            ;;
        postgres|pgsql)
            configured_database_connection "$backend" "$host" "$username" || return 1
            PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 pg_dump "${AF_DATABASE_ARGS[@]}" --no-password --clean --if-exists "$database" > "$backup/database.sql" 2> "$backup/postgres-recovery.log" || return 1
            [[ -s "$backup/database.sql" ]] || return 1
            PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password --quiet --tuples-only --no-align "--dbname=$database" --set=ON_ERROR_STOP=1 --file=- > "$backup/postgres-identity.sql" 2>> "$backup/postgres-recovery.log" <<'SQL' || return 1
SET search_path = pg_catalog;
SELECT 'SET LOCAL search_path = pg_catalog;';
SELECT format('DO %L;', format('BEGIN IF current_database() <> %L OR current_user <> %L OR (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()) <> %s THEN RAISE EXCEPTION ''Configured PostgreSQL database identity changed''; END IF; END', current_database(), current_user, oid))
FROM pg_catalog.pg_database WHERE datname = current_database();
SELECT format('DO %L;', format('BEGIN IF (SELECT default_version FROM pg_catalog.pg_available_extensions WHERE name = %L) IS DISTINCT FROM %L THEN RAISE EXCEPTION ''Configured PostgreSQL extension version cannot be reconstructed''; END IF; END', extname, extversion))
FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql';
SQL
            PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password --quiet --tuples-only --no-align "--dbname=$database" --set=ON_ERROR_STOP=1 --file=- > "$backup/postgres-schemas.sql" 2>> "$backup/postgres-recovery.log" <<'SQL' || return 1
SET search_path = pg_catalog;
DO $af_schema$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_namespace AS namespace
               CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS permissions
               WHERE namespace.nspname = 'public' AND permissions.grantor <> namespace.nspowner) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery requires public schema grants issued by the owner';
    END IF;
END
$af_schema$;
SELECT 'SELECT 1;';
SELECT format('CREATE SCHEMA public AUTHORIZATION %I; REVOKE ALL ON SCHEMA public FROM %I; COMMENT ON SCHEMA public IS %L;',
              pg_catalog.pg_get_userbyid(nspowner), pg_catalog.pg_get_userbyid(nspowner), pg_catalog.obj_description(oid, 'pg_namespace'))
FROM pg_catalog.pg_namespace WHERE nspname = 'public';
SELECT format('GRANT %s ON SCHEMA public TO %s%s;', permissions.privilege_type,
              CASE WHEN permissions.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(permissions.grantee)) END,
              CASE WHEN permissions.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END)
FROM pg_catalog.pg_namespace AS namespace
CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))) AS permissions
WHERE namespace.nspname = 'public';
SQL
            PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password --quiet --tuples-only --no-align "--dbname=$database" --set=ON_ERROR_STOP=1 --file=- > "$backup/postgres-metadata.sql" 2>> "$backup/postgres-recovery.log" <<'SQL' || return 1
SET search_path = pg_catalog;
DO $af_metadata$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_database AS database
               CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS permissions
               WHERE database.datname = current_database() AND permissions.grantor <> database.datdba) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery requires database grants issued by the owner';
    END IF;
END
$af_metadata$;
SELECT $af_database_sql$
DO $af_database$
DECLARE
    entry record;
BEGIN
    FOR entry IN SELECT DISTINCT permissions.grantee FROM pg_catalog.pg_database AS database
                 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba))) AS permissions
                 WHERE database.datname = current_database() LOOP
        EXECUTE format('REVOKE ALL ON DATABASE %I FROM %s CASCADE', current_database(),
                       CASE WHEN entry.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(entry.grantee)) END);
    END LOOP;
    FOR entry IN SELECT setrole FROM pg_catalog.pg_db_role_setting
                 WHERE setdatabase = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()) LOOP
        IF entry.setrole <> 0 THEN
            EXECUTE format('ALTER ROLE %I IN DATABASE %I RESET ALL', pg_catalog.pg_get_userbyid(entry.setrole), current_database());
        END IF;
    END LOOP;
END
$af_database$;
$af_database_sql$;
SELECT format('ALTER DATABASE %I RESET ALL;', current_database());
SELECT format('ALTER DATABASE %I CONNECTION LIMIT %s;', datname, datconnlimit)
FROM pg_catalog.pg_database WHERE datname = current_database();
SELECT format('COMMENT ON DATABASE %I IS %L;', datname, pg_catalog.shobj_description(oid, 'pg_database'))
FROM pg_catalog.pg_database WHERE datname = current_database();
SELECT format('GRANT %s ON DATABASE %I TO %s%s;', permissions.privilege_type, database.datname,
              CASE WHEN permissions.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(permissions.grantee)) END,
              CASE WHEN permissions.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END)
FROM pg_catalog.pg_database AS database
CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba))) AS permissions
WHERE database.datname = current_database();
SELECT format('SELECT pg_catalog.set_config(%L, %L, true); %s SET %I FROM CURRENT;',
              split_part(setting, '=', 1), substr(setting, strpos(setting, '=') + 1),
              CASE WHEN settings.setrole = 0 THEN format('ALTER DATABASE %I', current_database())
                   ELSE format('ALTER ROLE %I IN DATABASE %I', pg_catalog.pg_get_userbyid(settings.setrole), current_database()) END,
              split_part(setting, '=', 1))
FROM pg_catalog.pg_db_role_setting AS settings CROSS JOIN LATERAL unnest(settings.setconfig) AS setting
WHERE settings.setdatabase = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database());
SQL
            configured_postgresql_cleanup > "$backup/postgres-clean.sql" || return 1
            if ! PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password "--dbname=$database" --set=ON_ERROR_STOP=1 --single-transaction --file="$backup/postgres-identity.sql" --file="$backup/postgres-clean.sql" --file="$backup/postgres-schemas.sql" --file="$backup/database.sql" --file="$backup/postgres-metadata.sql" --command=ROLLBACK >> "$backup/postgres-recovery.log" 2>&1; then
                print_error "Configured PostgreSQL recovery preflight failed; refusing to migrate"
                return 1
            fi
            printf '%s\n' in-database-v1 > "$backup/.af-postgres-ready" || return 1
            ;;
        sqlite|sqlite3)
            [[ "$sqlite_path" == /* && ( ! -e "$sqlite_path" || -f "$sqlite_path" ) ]] || return 1
            validate_config_paths "$sqlite_path" "${sqlite_path}-wal" "${sqlite_path}-shm" || return 1
            snapshot_app_state "$backup" "$sqlite_path" "${sqlite_path}-wal" "${sqlite_path}-shm" || return 1
            ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$database" > "$backup/.af-database-ready"
)

restore_configured_database() (
    local backup="$1" backend="$2" database="$3" host="$4" username="$5" password="$6" sqlite_path="$7" artifact
    umask 077
    [[ "$backup" == /* && "$backup" != / && ! -L "$backup" ]] || return 1
    validate_config_paths "$backup/.af-database-ready" || return 1
    [[ -f "$backup/.af-database-ready" ]] || return 0
    [[ "$database" =~ ^[A-Za-z0-9_]+$ && "$(cat "$backup/.af-database-ready")" == "$database" ]] || return 1
    case "$backend" in
        mysql|mariadb)
            configured_database_connection "$backend" "$host" "$username" || return 1
            MYSQL_PWD="$password" af_logged mysql "${AF_DATABASE_ARGS[@]}" "$database" < "$backup/database.sql"
            ;;
        postgres|pgsql)
            configured_database_connection "$backend" "$host" "$username" || return 1
            for artifact in .af-postgres-ready postgres-identity.sql postgres-clean.sql postgres-schemas.sql database.sql postgres-metadata.sql postgres-recovery.log; do
                validate_config_paths "$backup/$artifact" || return 1
                [[ -f "$backup/$artifact" && ( "$artifact" == postgres-recovery.log || -s "$backup/$artifact" ) ]] || return 1
            done
            [[ "$(cat "$backup/.af-postgres-ready")" == in-database-v1 ]] || return 1
            af_logged printf '%s\n' 'Restoring configured PostgreSQL database in one transaction' || return 1
            if ! PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password "--dbname=$database" --set=ON_ERROR_STOP=1 --single-transaction --file="$backup/postgres-identity.sql" --file="$backup/postgres-clean.sql" --file="$backup/postgres-schemas.sql" --file="$backup/database.sql" --file="$backup/postgres-metadata.sql" >> "$backup/postgres-recovery.log" 2>&1; then
                print_error "Configured PostgreSQL recovery failed; retained database transaction was not committed"
                return 1
            fi
            ;;
        sqlite|sqlite3) restore_app_state "$backup" ;;
        *) return 1 ;;
    esac
)

backup_postgresql_database() {
    local backup="$1" database="$2" database_file relative
    [[ "$database" =~ ^[a-z_][a-z0-9_-]*$ && "$backup" == /* && "$backup" != / && ! -L "$backup" ]] || return 1
    mkdir -p -m 0700 -- "$backup" || return 1
    runuser -u postgres -- pg_dump --clean --if-exists --create "$database" > "$backup/$database.sql" || return 1
    if [[ -n "${AETHERFLOW_INSTALL_ROOT:-}" && /var/lib/postgresql == "${AETHERFLOW_INSTALL_ROOT%/}/"* && -d /var/lib/postgresql ]]; then
        [[ ! -L /var/lib/postgresql ]] || return 1
        while IFS= read -r -d '' database_file; do
            relative="${database_file#/var/lib/postgresql/}"
            mkdir -p -- "$backup/postgresql-database/$(dirname "$relative")" || return 1
            cp -a -- "$database_file" "$backup/postgresql-database/$relative" || return 1
        done < <(find /var/lib/postgresql -type f \( -name "*${database}*" -o -name "fixture-${database#af_}-schema" \) -print0)
    fi
    printf '%s\n' "$database" > "$backup/.af-database-ready"
}

restore_postgresql_database() {
    local backup="$1" database="$2" restored=true database_file relative
    [[ -f "$backup/.af-database-ready" ]] || return 0
    [[ "$database" =~ ^[a-z_][a-z0-9_-]*$ && ! -L "$backup" && ! -L "$backup/.af-database-ready" && ! -L "$backup/$database.sql" && "$(cat "$backup/.af-database-ready")" == "$database" ]] || return 1
    af_logged runuser -u postgres -- psql -d postgres -v ON_ERROR_STOP=1 --set="database=$database" <<'SQL' || restored=false
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :'database' AND pid <> pg_backend_pid();
SQL
    af_logged runuser -u postgres -- psql -d postgres -v ON_ERROR_STOP=1 -f - < "$backup/$database.sql" || restored=false
    if [[ -n "${AETHERFLOW_INSTALL_ROOT:-}" && /var/lib/postgresql == "${AETHERFLOW_INSTALL_ROOT%/}/"* && -d "$backup/postgresql-database" ]]; then
        [[ ! -L "$backup/postgresql-database" && ! -L /var/lib/postgresql ]] || return 1
        while IFS= read -r -d '' database_file; do
            relative="${database_file#"$backup/postgresql-database/"}"
            safe_restore_path_from_backup "$database_file" "/var/lib/postgresql/$relative" || return 1
        done < <(find "$backup/postgresql-database" -type f \( -name "*${database}*" -o -name "fixture-${database#af_}-schema" \) -print0)
    fi
    if [[ "$restored" != true ]]; then
        print_error "Database recovery failed; backups retained in $backup"
        return 1
    fi
}

validate_config_paths() {
    safe_config_python "$@" <<'PYEOF'
import sys
for filename in sys.argv[1:]:
    try:
        with ManagedConfig(filename, create_parents=False):
            pass
    except FileNotFoundError:
        pass
PYEOF
}

write_config_file() {
    local content
    content="$(cat; printf '\001')"
    safe_config_python "$1" "${2:-0640}" "${content%$'\001'}" <<'PYEOF'
import sys
safe_write_text(sys.argv[1], sys.argv[3], int(sys.argv[2], 8))
PYEOF
}

set_config_file_mode() {
    safe_config_python "$@" <<'PYEOF'
import sys
mode = int(sys.argv[1], 8)
for filename in sys.argv[2:]:
    with ManagedConfig(filename, create_parents=False) as config:
        if config.descriptor is None:
            raise FileNotFoundError(filename)
        config.check_target()
        os.fchmod(config.descriptor, mode)
        config.check_target()
PYEOF
}

# Discover effective local Servarr URLs and API keys from bounded, verified
# config.xml files and synchronize Notifiarr or Unpackerr TOML configs
# without clobbering operator-edited sections or exposing keys in logs.
sync_servarr_toml_config() {
    local consumer="$1"
    local target_config="$2"
    local app_port="${3:-}"
    local log_dir="${4:-}"
    local summary line level message
    summary="$(safe_config_python "$consumer" "$target_config" "$app_port" "$log_dir" <<'PYEOF'
from collections.abc import MutableMapping
import ipaddress
import os
import re
import socket
import sys
import xml.etree.ElementTree as ET

import tomlkit
from tomlkit.exceptions import TOMLKitError
from tomlkit.items import AoT, Table

PORTS = {"sonarr": 8989, "radarr": 7878, "lidarr": 8686, "readarr": 8787, "prowlarr": 9696}
MANAGED = re.compile(r"(?:^| \| )aetherflow-managed (\S+)$")


def local_address(value):
    host = (value or "").strip()
    if host in ("", "*", "localhost", "0.0.0.0"):
        return "127.0.0.1"
    if host in ("::", "[::]"):
        return "[::1]"
    address = ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
    if address.is_multicast or address.is_link_local:
        raise ValueError("unsupported BindAddress")
    if not address.is_loopback:
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.bind((str(address), 0))
        except OSError:
            raise ValueError("BindAddress is not local") from None
    return f"[{address}]" if address.version == 6 else str(address)


def read_upstream(app):
    try:
        with ManagedConfig(f"/var/lib/{app}/config.xml", create_parents=False) as config:
            if config.descriptor is None:
                return None
            raw = config.read_bytes(max_bytes=256 * 1024)
            config.check_target()
    except FileNotFoundError:
        return None

    try:
        xml = raw.decode("utf-8-sig")
        if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
            raise ValueError("unsupported XML declaration")
        document = ET.fromstring(xml)
        if document.tag != "Config":
            raise ValueError("unexpected XML root")
        key = (document.findtext("ApiKey") or "").strip()
        if not key or any(ord(char) < 32 or ord(char) == 127 for char in key):
            raise ValueError("missing or invalid API key")
        port = int((document.findtext("Port") or "").strip() or PORTS[app])
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        base = (document.findtext("UrlBase") or "").strip().rstrip("/")
        if base:
            base = base if base.startswith("/") else f"/{base}"
            if not re.fullmatch(r"/[A-Za-z0-9._/-]*", base) or any(
                part in ("", ".", "..") for part in base[1:].split("/")
            ):
                raise ValueError("invalid URL base")
        return f"http://{local_address(document.findtext('BindAddress'))}:{port}{base}", key
    except (ET.ParseError, ValueError):
        # Parser errors can include configuration excerpts. Keep XML out of logs.
        print(f"WARN: Skipped {app} integration because config.xml is incomplete or invalid")
        return None


def fresh_config(consumer, app_port, log_dir):
    result = tomlkit.document()
    if consumer == "notifiarr":
        port = int(app_port)
        if not 1 <= port <= 65535 or not log_dir:
            raise ValueError("Invalid Notifiarr configuration settings")
        result.add(tomlkit.comment("Notifiarr configuration"))
        defaults = {
            "api_key": "", "bind_addr": f"127.0.0.1:{port}", "ui_password": "",
            "urlbase": "/", "quiet": False,
            "log_file": os.path.join(log_dir, "app.log"),
            "http_log": os.path.join(log_dir, "http.log"),
        }
    else:
        result.add(tomlkit.comment("Unpackerr Configuration - Generated by AetherFlow"))
        defaults = {
            "debug": False, "quiet": False, "error_stderr": False, "activity": False,
            "log_queues": "1m", "log_files": 10, "log_file_mb": 10, "interval": "2m",
            "start_delay": "1m", "retry_delay": "5m", "max_retries": 3, "parallel": 1,
            "file_mode": "0644", "dir_mode": "0755",
        }
    result.update(defaults)
    return result


def get_managed_table(document, consumer, app, key):
    group = document.get(app)
    if isinstance(group, AoT):
        tables = list(group)
    elif consumer == "unpackerr" and isinstance(group, MutableMapping):
        tables = [entry for entry in group.values() if isinstance(entry, Table)]
    else:
        return None
    expected_name = f"AetherFlow {app.capitalize()}"
    stock_url = f"http://127.0.0.1:{PORTS[app]}"
    for table in tables:
        if consumer == "notifiarr" and table.get("name", expected_name) != expected_name:
            continue
        url = table.get("url")
        saved_key = table.get("api_key")
        comment = table.trivia.comment.removeprefix("#").strip()
        marker = MANAGED.search(comment)
        if marker and url in (None, "", marker[1]) and saved_key in (None, "", key):
            return table
        if not marker and isinstance(url, str) and url.rstrip("/") == stock_url and saved_key == key:
            if consumer != "notifiarr" or table.get("name") == expected_name:
                return table
    return None


def update_integration(document, consumer, app, url, key):
    if app not in document:
        table = tomlkit.table()
        if consumer == "notifiarr":
            table["name"] = f"AetherFlow {app.capitalize()}"
            group = tomlkit.aot()
            group.append(table)
            document[app] = group
        else:
            paths = ["/downloads", "/mnt/unionfs"]
            if app in ("sonarr", "radarr"):
                paths.append("/var/lib/rtorrent/downloads")
            table.update({"paths": paths, "protocols": "torrent", "timeout": "10s", "delete_orig": False})
            group = tomlkit.table(is_super_table=True)
            group["0"] = table
            document[app] = group
    else:
        table = get_managed_table(document, consumer, app, key)
        if table is None:
            print(f"INFO: Preserved operator-configured {app} integration")
            return

    if table.get("url") != url:
        table["url"] = url
    if not table.get("api_key"):
        table["api_key"] = key
    existing_comment = table.trivia.comment.removeprefix("#").strip()
    operator_comment = MANAGED.sub("", existing_comment)
    managed_comment = " | ".join(filter(None, (operator_comment, f"aetherflow-managed {url}")))
    if managed_comment != existing_comment:
        table.comment(managed_comment)
    print(f"INFO: Configured local {app} integration")


def sync(consumer, path, app_port, log_dir):
    if consumer not in ("notifiarr", "unpackerr"):
        raise ValueError("Unsupported Servarr integration consumer")
    apps = [app for app in PORTS if consumer == "notifiarr" or app != "prowlarr"]
    discovered = {app: value for app in apps if (value := read_upstream(app)) is not None}
    with ManagedConfig(path, create_parents=True) as config:
        existing = config.read_text(max_bytes=1024 * 1024)
        try:
            document = tomlkit.parse(existing) if existing.strip() else fresh_config(consumer, app_port, log_dir)
        except TOMLKitError:
            print(f"WARN: Preserved {consumer} configuration because its TOML could not be parsed")
            return
        if consumer == "unpackerr":
            # Unpackerr v1 enables a network listener and rewrites the config
            # to persist a UI password unless the listen address is empty.
            webserver = document.get("webserver")
            if webserver is None:
                webserver = tomlkit.table()
                document["webserver"] = webserver
            if isinstance(webserver, MutableMapping) and "listen_addr" not in webserver:
                webserver["listen_addr"] = ""

        for app, (url, key) in discovered.items():
            update_integration(document, consumer, app, url, key)
        if consumer == "unpackerr" and not existing.strip():
            for app in ("sonarr", "radarr"):
                if app not in discovered:
                    document.add(tomlkit.nl())
                    document.add(tomlkit.comment(f"[{app}.0]"))
                    document.add(tomlkit.comment(f'  url = "http://127.0.0.1:{PORTS[app]}"'))
                    document.add(tomlkit.comment('  api_key = ""'))
                    document.add(tomlkit.comment('  paths = ["/downloads", "/mnt/unionfs"]'))
        rendered = document.as_string()
        if rendered != existing:
            config.write_text(rendered, 0o600)
    if not discovered:
        print(f"INFO: No local Servarr upstreams configured for {consumer}; reinstall after installing Servarr apps")


sync(*sys.argv[1:5])
PYEOF
    )" || return $?
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        level="${line%%:*}"
        message="${line#*: }"
        case "$level" in
            WARN)
                if declare -F log_warn >/dev/null 2>&1; then
                    log_warn "$message"
                fi
                ;;
            INFO)
                if declare -F log_info >/dev/null 2>&1; then
                    log_info "$message"
                fi
                ;;
        esac
    done <<< "$summary"
}

# Change one listen setting without rebuilding the user's application config.
# Supported formats use only Python's standard library on the Debian host.
set_config_value() {
    AF_CFG_FILE="$1" AF_CFG_FORMAT="$2" AF_CFG_KEY="$3" AF_CFG_VALUE="$4" AF_CFG_SECTION="${5:-}" python3 - <<'PYEOF'
import json, os, pathlib, re, secrets, stat, sys, xml.etree.ElementTree as ET
filename, kind, key, value, section = (os.environ.pop('AF_CFG_' + name) for name in ('FILE', 'FORMAT', 'KEY', 'VALUE', 'SECTION'))
path = pathlib.Path(filename)
if not path.is_absolute() or '..' in path.parts:
    raise ValueError('Invalid managed configuration path')
directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
for component in path.parts[1:-1]:
    try:
        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    except FileNotFoundError:
        os.mkdir(component, 0o750, dir_fd=directory)
        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    os.close(directory)
    directory = child
metadata = None
try:
    descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
except FileNotFoundError:
    text = ''
else:
    with os.fdopen(descriptor) as existing:
        metadata = os.fstat(existing.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError('Managed configuration is not a regular file')
        if metadata.st_nlink != 1:
            raise ValueError('Refusing hardlinked managed configuration')
        if any(marker in key.lower() for marker in ('pass', 'secret', 'token', 'key', 'auth')) or path.name in ('nzbget.conf', 'sabnzbd.ini', 'config.ini'):
            os.fchmod(existing.fileno(), 0o600)
        text = existing.read()
if kind == 'xml':
    root = ET.fromstring(text) if text.strip() else ET.Element(section or 'Config')
    node = root.find(key)
    if node is None:
        node = ET.SubElement(root, key)
    node.text = value
    text = ET.tostring(root, encoding='unicode') + '\n'
elif kind == 'json':
    data = json.loads(text) if text.strip() else {}
    parent = data
    parts = key.split('.')
    for part in parts[:-1]:
        parent = parent.setdefault(part, {})
    parent[parts[-1]] = int(value) if value.isdecimal() else value
    text = json.dumps(data, indent=2) + '\n'
elif kind == 'js':
    pattern = re.compile(r'(\b' + re.escape(key) + r'\s*:\s*)\d+')
    if not pattern.search(text):
        raise ValueError('Cannot locate existing JavaScript port setting')
    text = pattern.sub(lambda m: m.group(1) + value, text, count=1)
else:
    if kind == 'yaml':
        header = re.compile(r'(?m)^' + re.escape(section) + r':\s*(?:#.*)?$') if section else None
        pattern = re.compile(r'(?m)^' + ('  ' if section else '') + re.escape(key) + r'\s*:.*$')
        setting = ('  ' if section else '') + key + ': ' + value + '\n'
        next_section = re.compile(r'(?m)^\S[^\n]*:')
    elif kind == 'env':
        header = None
        pattern = re.compile(r'(?m)^' + re.escape(key) + r'=.*$')
        setting = key + '=' + value + '\n'
        next_section = re.compile(r'(?!)')
    elif kind == 'ini':
        header = re.compile(r'(?m)^\[' + re.escape(section) + r'\]\s*$') if section else None
        pattern = re.compile(r'(?im)^\s*' + re.escape(key) + r'\s*=.*$')
        setting = key + ' = ' + value + '\n'
        next_section = re.compile(r'(?m)^\[')
    else:
        raise ValueError('Unsupported config format: ' + kind)
    start, end = 0, len(text)
    if header:
        match = header.search(text)
        if match is None:
            text += ('\n' if text and not text.endswith('\n') else '') + (section + ':\n' if kind == 'yaml' else '[' + section + ']\n')
            start = end = len(text)
        else:
            start = match.end() + 1
            following = next_section.search(text, start)
            end = following.start() if following else len(text)
    block = text[start:end]
    if pattern.search(block):
        block = pattern.sub(lambda _: setting.rstrip('\n'), block)
    else:
        block = block.rstrip('\n') + ('\n' if block else '') + setting
    text = text[:start] + block + text[end:]
temporary = '.af-config.' + secrets.token_hex(12)
try:
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(descriptor, 'w') as output:
        mode = stat.S_IMODE(metadata.st_mode) & 0o660 if metadata else 0o600
        if any(marker in key.lower() for marker in ('pass', 'secret', 'token', 'key', 'auth')) or path.name in ('nzbget.conf', 'sabnzbd.ini', 'config.ini'):
            mode = 0o600
        if metadata:
            os.fchown(output.fileno(), metadata.st_uid, metadata.st_gid)
        os.fchmod(output.fileno(), mode)
        output.write(text)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
finally:
    try:
        os.unlink(temporary, dir_fd=directory)
    except FileNotFoundError:
        pass
    os.close(directory)
PYEOF
}

# Activate prepared application code while retaining persistent paths and a
# private copy of the previous installation for recovery after migrations.
replace_app_tree() {
    local staged="$1" destination="$2" relative backup
    shift 2
    for relative in "$@"; do
        if [[ "$relative" == /* || "$relative" == *..* ]]; then
            print_error "Invalid application data path: $relative"
            return 1
        fi
        if [[ -e "$destination/$relative" || -L "$destination/$relative" ]]; then
            mkdir -p "$(dirname "$staged/$relative")"
            rm -rf -- "$staged/$relative"
            cp -a -- "$destination/$relative" "$staged/$relative"
        fi
    done
    if [[ -f "$destination/.af-version" && ! -L "$destination/.af-version" ]]; then
        validate_config_paths "$destination/.af-version" || return 1
        cp -p --remove-destination -- "$destination/.af-version" "$staged/.af-version" || return 1
    fi
    if [[ -e "$destination" ]]; then
        backup="$(mktemp -d "${destination}.af-backup.XXXXXX")"
        chmod 700 "$backup"
        mv -T "$destination" "$backup/app"
        if ! mv -T "$staged" "$destination"; then
            mv -T "$backup/app" "$destination"
            return 1
        fi
        log_info "Previous application files retained in $backup/app"
        prune_app_archive_backups "$destination" "" "$backup" 2
    else
        mv -T "$staged" "$destination"
    fi
}

stage_app_archive() {
    local archive="$1" destination="$2" executable="$3" state="$4" unit="$5"
    local archive_root="${6:-${executable%%|*}}" candidate found=false relative entry state_index extracted backup
    local -a candidates=()
    IFS='|' read -r -a candidates <<< "$executable"
    [[ ! -L "$destination" && ! -L "$state" ]] || return 1
    for backup in "${destination}".af-backup.??????; do
        [[ -d "$backup" && ! -L "$backup" && -f "$backup/.af-archive-owner" && ! -L "$backup/.af-archive-owner" ]] || continue
        if [[ "$(cat "$backup/.af-archive-owner")" == "$unit" && -e "$backup/.af-archive-pending" ]]; then
            print_error "An interrupted application update needs recovery before retrying: $backup"
            return 1
        fi
    done
    AF_ARCHIVE_DESTINATION="$destination"
    AF_ARCHIVE_STATE_PATHS=()
    AF_ARCHIVE_ROLLBACK_RESTART_UNITS=()
    AF_ARCHIVE_ROLLBACK_HOOK=""
    for entry in "$state" "${7:-}"; do
        [[ -n "$entry" ]] || continue
        [[ ! -L "$entry" ]] || return 1
        AF_ARCHIVE_STATE_PATHS+=("$entry")
        if [[ "$entry" == *.db ]]; then
            AF_ARCHIVE_STATE_PATHS+=("${entry}-wal" "${entry}-shm")
        fi
    done
    AF_ARCHIVE_UNIT="$unit"
    AF_ARCHIVE_TIMER_UNIT=""
    AF_ARCHIVE_TIMER_ACTIVE=false
    AF_ARCHIVE_TIMER_ENABLED=false
    AF_ARCHIVE_SOCKET_UNIT=""
    AF_ARCHIVE_SOCKET_ACTIVE=false
    AF_ARCHIVE_SOCKET_ENABLED=false
    if [[ "$unit" != *.timer && "$unit" != *.socket ]]; then
        AF_ARCHIVE_TIMER_UNIT="${unit%.service}.timer"
        AF_ARCHIVE_SOCKET_UNIT="${unit%.service}.socket"
    fi
    AF_ARCHIVE_ARCHIVE="$archive"
    AF_ARCHIVE_ACTIVATED=false
    AF_ARCHIVE_ORIGINAL_PRESENT=false
    [[ ! -e "$destination" ]] || AF_ARCHIVE_ORIGINAL_PRESENT=true
    AF_ARCHIVE_STOPPED=false
    AF_ARCHIVE_PREVIOUS=false
    [[ "${9:-}" != binary || ! -f "$destination" ]] || AF_ARCHIVE_PREVIOUS=true
    for candidate in "${candidates[@]}"; do
        [[ ! -e "$destination/$candidate" ]] || AF_ARCHIVE_PREVIOUS=true
    done
    AF_ARCHIVE_BACKUP="$(mktemp -d "${destination}.af-backup.XXXXXX")"
    chmod 700 "$AF_ARCHIVE_BACKUP"
    printf '%s\n' "$unit" > "$AF_ARCHIVE_BACKUP/.af-archive-owner"
    trap 'rollback_app_archive_update $?' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    export AF_TX_DIR="$AF_ARCHIVE_BACKUP"
    mkdir -m 0700 -- "$AF_TX_DIR/pre_versions" || return 1
    for entry in "$destination" "${AF_ARCHIVE_STATE_PATHS[@]}"; do
        if [[ -f "$entry/.af-version" && ! -L "$entry/.af-version" ]]; then
            validate_config_paths "$entry/.af-version" || return 1
            mkdir -p -m 0700 -- "$AF_TX_DIR/pre_versions$entry" || return 1
            install -m 0600 -- "$entry/.af-version" "$AF_TX_DIR/pre_versions$entry/.af-version" || return 1
        fi
    done
    mkdir "$AF_ARCHIVE_BACKUP/release"
    python3 - "$AF_ARCHIVE_BACKUP/recovery.json" "$destination" "$unit" "${AF_ARCHIVE_STATE_PATHS[@]}" <<'PYEOF'
import json, os, sys
with open(sys.argv[1], 'x') as output:
    json.dump({'destination': sys.argv[2], 'unit': sys.argv[3], 'state_paths': sys.argv[4:]}, output)
    output.flush()
    os.fsync(output.fileno())
PYEOF
    extracted="$AF_ARCHIVE_BACKUP/release"
    [[ "$archive_root" == . ]] || extracted="${extracted}/${archive_root}"
    if [[ -d "$archive" && ! -L "$archive" ]]; then
        mv -T -- "$archive" "$AF_ARCHIVE_BACKUP/release/prepared"
        extracted="$AF_ARCHIVE_BACKUP/release/prepared"
        AF_ARCHIVE_ARCHIVE=""
    else
        python3 - "$archive" "$AF_ARCHIVE_BACKUP/release" <<'PYEOF'
import pathlib, sys, tarfile
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    if hasattr(tarfile, 'data_filter'):
        archive.extractall(sys.argv[2], filter='data')
    else:
        members = archive.getmembers()
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isdir() or member.isfile()):
                raise ValueError('Unsafe archive member; link archives require updated Python tar filters')
            member.mode &= 0o777
            member.uid = member.gid = -1
            member.uname = member.gname = ''
        if hasattr(tarfile, 'fully_trusted_filter'):
            archive.extractall(sys.argv[2], members=members, filter=tarfile.fully_trusted_filter)
        else:
            archive.extractall(sys.argv[2], members=members)
PYEOF
    fi
    for candidate in "${candidates[@]}"; do
        if [[ -s "$extracted/$candidate" && -x "$extracted/$candidate" && ! -L "$extracted" && ! -L "$extracted/$candidate" ]]; then
            found=true
        fi
    done
    if [[ "$found" != true ]]; then
        print_error "The application archive does not contain the expected executable: $executable"
        return 1
    fi
    [[ "${9:-}" != binary ]] || extracted="$extracted/${candidates[0]}"
    touch "$AF_ARCHIVE_BACKUP/.af-archive-pending"
    if [[ -n "${AF_ARCHIVE_TIMER_UNIT:-}" ]]; then
        if systemctl is-active --quiet "$AF_ARCHIVE_TIMER_UNIT" 2>/dev/null; then
            AF_ARCHIVE_TIMER_ACTIVE=true
        fi
        if systemctl is-enabled --quiet "$AF_ARCHIVE_TIMER_UNIT" 2>/dev/null; then
            AF_ARCHIVE_TIMER_ENABLED=true
        fi
        if [[ -e "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" ]]; then
            cp -a -- "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" "$AF_ARCHIVE_BACKUP/timer_unit"
        fi
        if [[ "$AF_ARCHIVE_TIMER_ACTIVE" == true || -e "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" ]]; then
            stop_systemd_unit "$AF_ARCHIVE_TIMER_UNIT"
        fi
    fi
    if [[ -n "${AF_ARCHIVE_SOCKET_UNIT:-}" ]]; then
        if systemctl is-active --quiet "$AF_ARCHIVE_SOCKET_UNIT" 2>/dev/null; then
            AF_ARCHIVE_SOCKET_ACTIVE=true
        fi
        if systemctl is-enabled --quiet "$AF_ARCHIVE_SOCKET_UNIT" 2>/dev/null; then
            AF_ARCHIVE_SOCKET_ENABLED=true
        fi
        if [[ -e "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" ]]; then
            cp -a -- "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" "$AF_ARCHIVE_BACKUP/socket_unit"
        fi
        if [[ "$AF_ARCHIVE_SOCKET_ACTIVE" == true || -e "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" ]]; then
            stop_systemd_unit "$AF_ARCHIVE_SOCKET_UNIT"
        fi
    fi
    stop_systemd_unit "$unit"
    AF_ARCHIVE_STOPPED=true
    for state_index in "${!AF_ARCHIVE_STATE_PATHS[@]}"; do
        entry="${AF_ARCHIVE_STATE_PATHS[$state_index]}"
        if [[ -e "$entry" || -L "$entry" ]]; then
            cp -a -- "$entry" "$AF_ARCHIVE_BACKUP/data-${state_index}"
        fi
    done
    if [[ "${8:-}" == preserve ]]; then
        for entry in "$destination"/* "$destination"/.[!.]* "$destination"/..?*; do
            [[ -e "$entry" || -L "$entry" ]] || continue
            relative="${entry##*/}"
            [[ "$relative" != .af-version ]] || continue
            found=false
            for candidate in "${candidates[@]}"; do
                [[ "$relative" != "$candidate" ]] || found=true
            done
            [[ "$found" != true ]] || continue
            rm -rf -- "$extracted/$relative"
            cp -a -- "$entry" "$extracted/$relative"
        done
    fi
    if [[ -e "/etc/systemd/system/${unit}.service" ]]; then
        cp -a -- "/etc/systemd/system/${unit}.service" "$AF_ARCHIVE_BACKUP/unit"
    fi
    if [[ "${9:-}" != binary && -f "$AF_TX_DIR/pre_versions$destination/.af-version" ]]; then
        cp -p --remove-destination -- "$AF_TX_DIR/pre_versions$destination/.af-version" "$extracted/.af-version" || return 1
    fi
    AF_ARCHIVE_ACTIVATED=true
    if [[ -e "$destination" ]]; then
        mv -T -- "$destination" "$AF_ARCHIVE_BACKUP/app"
    fi
    mv -T -- "$extracted" "$destination"
    [[ -z "$AF_ARCHIVE_ARCHIVE" ]] || rm -f -- "$archive"
}

rollback_app_archive_update() {
    local status="$1" restored=true state_index entry
    trap - EXIT INT TERM
    set +e
    [[ "${INSTALL_COMMITTED:-false}" != true ]] || exit "$status"
    [[ "$status" -ne 0 ]] || status=1
    if [[ "${AF_ARCHIVE_ACTIVATED:-false}" == true && ( "${AF_ARCHIVE_ORIGINAL_PRESENT:-false}" != true || -e "${AF_ARCHIVE_BACKUP:-}/app" ) ]]; then
        local -a quiesce_units=()
        if [[ -n "${AF_ARCHIVE_TIMER_UNIT:-}" && ( -e "${AF_ARCHIVE_BACKUP:-}/timer_unit" || -e "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" || "${AF_ARCHIVE_TIMER_ACTIVE:-false}" == true ) ]]; then
            quiesce_units+=("$AF_ARCHIVE_TIMER_UNIT")
        fi
        if [[ -n "${AF_ARCHIVE_SOCKET_UNIT:-}" && ( -e "${AF_ARCHIVE_BACKUP:-}/socket_unit" || -e "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" || "${AF_ARCHIVE_SOCKET_ACTIVE:-false}" == true ) ]]; then
            quiesce_units+=("$AF_ARCHIVE_SOCKET_UNIT")
        fi
        quiesce_units+=("$AF_ARCHIVE_UNIT")
        if ! quiesce_services_for_rollback "${quiesce_units[@]}"; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt "$status" "rollback" "incomplete_rollback" "Application archive rollback aborted because service quiescence failed; recovery backup preserved at ${AF_ARCHIVE_BACKUP:-unknown} (incomplete-rollback)"
            else
                printf 'AF_DIAG_FAILURE={"stage":"rollback","exit_code":%d,"category":"incomplete_rollback","summary":"Application archive rollback aborted because service quiescence failed; recovery backup preserved at %s (incomplete-rollback)"}\n' "$status" "${AF_ARCHIVE_BACKUP:-unknown}" >&2
            fi
            exit "$status"
        fi
        safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/app" "$AF_ARCHIVE_DESTINATION" || restored=false
        for state_index in "${!AF_ARCHIVE_STATE_PATHS[@]}"; do
            entry="${AF_ARCHIVE_STATE_PATHS[$state_index]}"
            safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/data-${state_index}" "$entry" || restored=false
        done
        if [[ -n "${AF_ARCHIVE_DATABASE_BACKUP:-}" ]]; then
            restore_configured_database "$AF_ARCHIVE_DATABASE_BACKUP" "${AF_ARCHIVE_DATABASE_CONFIG[@]}" || restored=false
        fi
        if [[ -e "$AF_ARCHIVE_BACKUP/unit" ]]; then
            safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/unit" "/etc/systemd/system/${AF_ARCHIVE_UNIT}.service" || restored=false
        elif [[ -e "/etc/systemd/system/${AF_ARCHIVE_UNIT}.service" || -L "/etc/systemd/system/multi-user.target.wants/${AF_ARCHIVE_UNIT}.service" ]] || systemctl is-enabled --quiet "$AF_ARCHIVE_UNIT" 2>/dev/null; then
            af_logged systemctl disable -- "$AF_ARCHIVE_UNIT" || restored=false
            rm -f -- "/etc/systemd/system/${AF_ARCHIVE_UNIT}.service" || restored=false
        fi
        if [[ -n "${AF_ARCHIVE_TIMER_UNIT:-}" ]]; then
            if [[ -e "$AF_ARCHIVE_BACKUP/timer_unit" ]]; then
                safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/timer_unit" "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" || restored=false
            elif [[ -e "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" ]]; then
                af_logged systemctl disable -- "$AF_ARCHIVE_TIMER_UNIT" || restored=false
                rm -f -- "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" || restored=false
            fi
        fi
        if [[ -n "${AF_ARCHIVE_SOCKET_UNIT:-}" ]]; then
            if [[ -e "$AF_ARCHIVE_BACKUP/socket_unit" ]]; then
                safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/socket_unit" "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" || restored=false
                if [[ "${AF_ARCHIVE_SOCKET_ENABLED:-false}" != true ]]; then
                    af_logged systemctl disable -- "$AF_ARCHIVE_SOCKET_UNIT" || restored=false
                fi
            elif [[ -e "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" || -L "/etc/systemd/system/sockets.target.wants/${AF_ARCHIVE_SOCKET_UNIT}" ]]; then
                af_logged systemctl disable -- "$AF_ARCHIVE_SOCKET_UNIT" || restored=false
                rm -f -- "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" "/etc/systemd/system/sockets.target.wants/${AF_ARCHIVE_SOCKET_UNIT}" || restored=false
                rm -rf -- "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}.d" || restored=false
            fi
        fi
        af_logged systemctl daemon-reload || restored=false
    fi
    if [[ "$restored" == true && -n "${AF_ARCHIVE_ROLLBACK_HOOK:-}" ]] && declare -F "$AF_ARCHIVE_ROLLBACK_HOOK" >/dev/null 2>&1; then
        "$AF_ARCHIVE_ROLLBACK_HOOK" || restored=false
    fi
    if [[ "$restored" == true ]]; then
        for entry in "${AF_ARCHIVE_ROLLBACK_RESTART_UNITS[@]}"; do
            af_logged systemctl restart "$entry" || restored=false
        done
    fi
    if [[ "$restored" == true && -n "${AF_ARCHIVE_SOCKET_UNIT:-}" && -e "$AF_ARCHIVE_BACKUP/socket_unit" ]]; then
        if [[ "${AF_ARCHIVE_SOCKET_ENABLED:-false}" == true ]]; then
            af_logged systemctl enable -- "$AF_ARCHIVE_SOCKET_UNIT" || restored=false
        fi
        if [[ "$restored" == true && "${AF_ARCHIVE_SOCKET_ACTIVE:-false}" == true ]]; then
            af_logged systemctl restart "$AF_ARCHIVE_SOCKET_UNIT" || restored=false
        fi
    fi
    if [[ "$restored" == true && "${AF_ARCHIVE_STOPPED:-false}" == true && "${AF_ARCHIVE_PREVIOUS:-false}" == true ]]; then
        af_logged systemctl restart "$AF_ARCHIVE_UNIT" || restored=false
    fi
    if [[ "$restored" == true && -n "${AF_ARCHIVE_TIMER_UNIT:-}" ]]; then
        if [[ "${AF_ARCHIVE_TIMER_ENABLED:-false}" == true ]]; then
            af_logged systemctl enable -- "$AF_ARCHIVE_TIMER_UNIT" || restored=false
        fi
        if [[ "$restored" == true && "${AF_ARCHIVE_TIMER_ACTIVE:-false}" == true ]]; then
            af_logged systemctl restart "$AF_ARCHIVE_TIMER_UNIT" || restored=false
        fi
    fi
    rm -f -- "${AF_ARCHIVE_ARCHIVE:-}"
    rm -rf -- "${AF_ARCHIVE_BACKUP:-}/release"
    if [[ "$restored" != true ]]; then
        if declare -F af_write_failure_receipt >/dev/null 2>&1; then
            af_write_failure_receipt "$status" "rollback" "incomplete_rollback" "Application recovery is incomplete; recovery backup preserved at ${AF_ARCHIVE_BACKUP:-unknown} (incomplete-rollback)"
        else
            printf 'AF_DIAG_FAILURE={"stage":"rollback","exit_code":%d,"category":"incomplete_rollback","summary":"Application recovery is incomplete; recovery backup preserved at %s (incomplete-rollback)"}\n' "$status" "${AF_ARCHIVE_BACKUP:-unknown}" >&2
        fi
        print_error "Application recovery is incomplete; recovery backup preserved at ${AF_ARCHIVE_BACKUP:-unknown}"
    else
        [[ -z "${AF_ARCHIVE_BACKUP:-}" ]] || rm -f -- "$AF_ARCHIVE_BACKUP/.af-archive-pending"
    fi
    exit "$status"
}

# Retain the newest N (default 2) completed ${destination}.af-backup.* directories
# for the same owner, mirroring retain_successful_app_backups() while skipping
# symlinks, pending/in-flight backups (.af-archive-pending), and foreign owners.
prune_app_archive_backups() {
    local destination="$1" expected_owner="${2:-}" keep_path="${3:-}" keep_count="${4:-2}"
    [[ -n "$destination" && ! -L "$destination" ]] || return 0
    [[ "$keep_count" =~ ^[0-9]+$ ]] || keep_count=2
    local obsolete=""
    obsolete="$(python3 - "$destination" "$expected_owner" "$keep_path" "$keep_count" <<'PYEOF'
import os, stat, sys

destination, expected_owner, keep_path, keep_count_raw = sys.argv[1:5]
keep_count = max(0, int(keep_count_raw))
parent = os.path.dirname(destination) or "/"
base = os.path.basename(destination)
prefix = base + ".af-backup."
keep_name = os.path.basename(keep_path) if keep_path and os.path.dirname(keep_path) == parent else ""

try:
    parent_st = os.lstat(parent)
    if stat.S_ISLNK(parent_st.st_mode) or not stat.S_ISDIR(parent_st.st_mode):
        sys.exit(0)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
except OSError:
    sys.exit(0)

try:
    candidates = []
    for name in os.listdir(parent_fd):
        if not name.startswith(prefix) or len(name) <= len(prefix):
            continue
        try:
            entry_st = os.lstat(name, dir_fd=parent_fd)
        except OSError:
            continue
        if stat.S_ISLNK(entry_st.st_mode) or not stat.S_ISDIR(entry_st.st_mode):
            continue
        try:
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        except OSError:
            continue
        try:
            try:
                os.lstat(".af-archive-pending", dir_fd=child_fd)
                continue
            except FileNotFoundError:
                pass
            owner_matched = True
            try:
                owner_st = os.lstat(".af-archive-owner", dir_fd=child_fd)
                if stat.S_ISLNK(owner_st.st_mode) or not stat.S_ISREG(owner_st.st_mode):
                    owner_matched = False
                else:
                    ofd = os.open(".af-archive-owner", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=child_fd)
                    with os.fdopen(ofd, "r", encoding="utf-8", errors="replace") as fh:
                        owner_val = fh.read(256).strip()
                    if expected_owner and owner_val != expected_owner:
                        owner_matched = False
                    elif not expected_owner and owner_val:
                        owner_matched = False
            except FileNotFoundError:
                pass
            if not owner_matched:
                continue
            candidates.append((entry_st.st_mtime_ns, name))
        finally:
            os.close(child_fd)

    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    kept = []
    if keep_name:
        kept.append(keep_name)
    for _, name in candidates:
        if name in kept:
            continue
        if len(kept) < keep_count:
            kept.append(name)
        else:
            print(os.path.join(parent, name))
finally:
    os.close(parent_fd)
PYEOF
    )" || return 0
    local dir
    while IFS= read -r dir; do
        [[ -n "$dir" && ! -L "$dir" && -d "$dir" ]] || continue
        rm -rf -- "$dir" || true
    done <<< "$obsolete"
}

finish_app_archive_update() {
    local unit="$1" port="$2" readiness_path="${3:-}"
    wait_for_service_ready "$unit" "$port" "$readiness_path" || return 1
    if [[ -n "${AF_ARCHIVE_BACKUP:-}" ]]; then
        rm -rf -- "$AF_ARCHIVE_BACKUP/release"
        log_info "Previous application and state retained privately in $AF_ARCHIVE_BACKUP"
        prune_app_archive_backups "${AF_ARCHIVE_DESTINATION:-}" "${AF_ARCHIVE_UNIT:-$unit}" "$AF_ARCHIVE_BACKUP" 2
    fi
}

retain_app_data_directory() {
    local source="$1" destination="$2"
    [[ ! -L "$destination" ]] || return 1
    if [[ -L "$source" ]]; then
        [[ "$(readlink -f -- "$source")" == "$(readlink -f -- "$destination")" ]] || return 1
        return 0
    fi
    [[ -d "$source" ]] || { mkdir -p -- "$destination"; return 0; }
    if [[ -d "$destination" ]] && [[ -n "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        print_error "Both legacy and retained data exist; reconcile $source and $destination before retrying"
        return 1
    fi
    mkdir -p -- "$destination"
    cp -a -- "$source/." "$destination/"
}

purge_app_archive_backups() {
    local package="$1" destination="$2" ownership="${3:-}" backup
    for backup in "${destination}".af-backup.*; do
        [[ -d "$backup" && ! -L "$backup" ]] || continue
        # Legacy replace_app_tree backups have no owner receipt. An explicit
        # destination still identifies them, while foreign receipts stay intact.
        if [[ -e "$backup/.af-archive-owner" || -L "$backup/.af-archive-owner" ]]; then
            [[ -f "$backup/.af-archive-owner" && ! -L "$backup/.af-archive-owner" ]] || continue
            [[ "$(cat "$backup/.af-archive-owner")" == "$package" ]] || continue
        elif [[ "$ownership" == require-owner ]]; then
            continue
        fi
        rm -rf -- "$backup" || return 1
    done
}
