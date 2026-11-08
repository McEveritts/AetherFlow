"""Exercise configured database recovery against private, socket-only PostgreSQL."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

from installer_test_helpers import common_functions


HELPERS = common_functions('backup_configured_database', 'restore_configured_database',
                           'snapshot_app_state', 'restore_app_state', 'safe_restore_path_from_backup', 'safe_rm_rf')
PASSWORD = 'configured-fixture-password-not-for-argv'


def postgres_binaries():
    candidates = [Path('/usr/lib/postgresql/17/bin')]
    candidates.extend(sorted(Path('/usr/lib/postgresql').glob('*/bin'), reverse=True))
    if shutil.which('initdb'):
        candidates.append(Path(shutil.which('initdb')).parent)
    return next((directory for directory in candidates
                 if all((directory / command).is_file()
                        for command in ('initdb', 'pg_ctl', 'psql', 'pg_dump'))), None)


class ConfiguredPostgreSQLRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = postgres_binaries()
        if cls.binary is None:
            raise unittest.SkipTest('PostgreSQL server/client binaries are not installed')
        if os.geteuid() == 0:
            raise unittest.SkipTest('Private PostgreSQL initdb requires an unprivileged test user')
        cls.temporary = tempfile.TemporaryDirectory(prefix='af-pg-', dir=os.environ.get('TMPDIR'))
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.data = cls.root / 'data'
        cls.socket = cls.root / 'socket'
        cls.socket.mkdir(mode=0o700)
        cls.environment = {key: value for key, value in os.environ.items()
                           if not key.startswith(('PG', 'MYSQL'))}
        cls.environment.update(PATH=str(cls.binary) + os.pathsep + os.environ['PATH'],
                               PGHOST=str(cls.socket), PGPORT='5432', PGUSER='af_test_admin',
                               PGDATABASE='postgres', PGCONNECT_TIMEOUT='5',
                               PGPASSFILE=str(cls.root / 'no-password-file'), PGSERVICEFILE='/dev/null')
        cls.run_command([str(cls.binary / 'initdb'), '-D', str(cls.data), '-U', 'af_test_admin',
                         '--auth-local=trust', '--auth-host=reject', '--no-locale',
                         '--encoding=UTF8', '--no-sync'])
        cls.addClassCleanup(cls.stop_cluster)
        options = (f"-c listen_addresses='' -c unix_socket_directories='{cls.socket}' "
                   '-c unix_socket_permissions=0700 -c shared_buffers=16MB -c max_connections=12')
        cls.run_command([str(cls.binary / 'pg_ctl'), '-D', str(cls.data), '-l', str(cls.root / 'postgres.log'),
                         '-w', '-t', '20', '-o', options, 'start'])
        cls.query('postgres', 'CREATE ROLE af_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; '
                  'CREATE ROLE "af_$af_identity$_owner" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; '
                  'CREATE ROLE af_reader LOGIN; CREATE ROLE af_migration_reader; '
                  'CREATE ROLE af_foreign_owner;')
        cls.query('postgres', 'CREATE DATABASE unrelated_app')
        cls.query('unrelated_app', "CREATE TABLE sentinel(value text); INSERT INTO sentinel VALUES ('untouched')")
        cls.query('postgres', 'GRANT CONNECT, TEMPORARY ON DATABASE unrelated_app TO af_app WITH GRANT OPTION; '
                  'GRANT CONNECT ON DATABASE unrelated_app TO af_reader')
        cls.unrelated_metadata = cls.query('postgres', "SELECT row(datdba, datacl, datconnlimit)::text "
                                          "FROM pg_database WHERE datname='unrelated_app'")

    @classmethod
    def run_command(cls, command, *, input=None, check=True, environment=None):
        result = subprocess.run(command, input=input, text=True, capture_output=True,
                                env=environment or cls.environment, timeout=45)
        if check and result.returncode:
            raise AssertionError(f'{command[0]} failed ({result.returncode}):\n{result.stdout}\n{result.stderr}')
        return result

    @classmethod
    def query(cls, database, sql, username='af_test_admin'):
        return cls.run_command([str(cls.binary / 'psql'), '-X', '-q', '-A', '-t', '-w',
                                '-v', 'ON_ERROR_STOP=1', '-U', username, '-d', database],
                               input=sql).stdout.strip()

    @classmethod
    def stop_cluster(cls):
        if (cls.data / 'postmaster.pid').exists():
            cls.run_command([str(cls.binary / 'pg_ctl'), '-D', str(cls.data), '-w', '-t', '20',
                             '-m', 'immediate', 'stop'])

    def setUp(self):
        self.workspace = self.root / self._testMethodName
        self.workspace.mkdir(mode=0o700)
        self.backup = self.workspace / 'backup'
        self.database = 'configured_app'
        self.query('postgres', f'CREATE DATABASE {self.database} OWNER af_app')
        self.query(self.database, "CREATE TABLE retained(id bigserial PRIMARY KEY, value text NOT NULL); "
                   "INSERT INTO retained(value) VALUES ('before');", 'af_app')
        self.identity = self.query('postgres', f"SELECT oid FROM pg_database WHERE datname='{self.database}'")
        wrapper_directory = self.workspace / 'bin'
        wrapper_directory.mkdir()
        wrapper = f'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
with open(os.environ['AF_TEST_COMMANDS'], 'a') as output:
    output.write(json.dumps([Path(sys.argv[0]).name, *sys.argv[1:]]) + '\\n')
os.execv(str(Path({str(self.binary)!r}) / Path(sys.argv[0]).name), sys.argv)
'''
        for command in ('pg_dump', 'psql'):
            executable = wrapper_directory / command
            executable.write_text(wrapper)
            executable.chmod(0o700)
        self.helper_environment = {**self.environment, 'AF_TEST_PASSWORD': PASSWORD,
                                   'AF_TEST_COMMANDS': str(self.workspace / 'commands.jsonl'),
                                   'PATH': str(wrapper_directory) + os.pathsep + self.environment['PATH']}
        self.addCleanup(self.drop_configured_database)

    def drop_configured_database(self):
        self.query('postgres', f'DROP DATABASE IF EXISTS {self.database} WITH (FORCE)')

    def tearDown(self):
        self.assertEqual(self.query('unrelated_app', 'SELECT value FROM sentinel'), 'untouched')
        self.assertEqual(self.query('postgres', "SELECT row(datdba, datacl, datconnlimit)::text "
                                    "FROM pg_database WHERE datname='unrelated_app'"), self.unrelated_metadata)

    def helper(self, operation, *, backend='postgres', database=None, backup=None, username='af_app', check=True):
        program = HELPERS + '''
print_error() { printf '%s\\n' "$*" >&2; }
LOGFILE="$2/application.log"
"$1" "$3" "$4" "$5" "$6" "$7" "$AF_TEST_PASSWORD" ""
'''
        result = self.run_command(['bash', '-euc', program, 'fixture', operation, str(self.workspace),
                                   str(backup or self.backup), backend, database or self.database,
                                   str(self.socket), username], check=False, environment=self.helper_environment)
        if check:
            recovery_log = self.backup / 'postgres-recovery.log'
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr +
                             (recovery_log.read_text() if recovery_log.exists() else ''))
        return result

    def assert_identity_preserved(self):
        self.assertEqual(self.query('postgres', f"SELECT oid FROM pg_database WHERE datname='{self.database}'"), self.identity)

    def test_non_createdb_owner_restores_original_schema_and_data(self):
        self.assertEqual(self.query('postgres', "SELECT rolcreatedb OR rolsuper FROM pg_roles WHERE rolname='af_app'"), 'f')
        original_objects = self.query(self.database, "SELECT row('retained'::regclass::oid, 'retained_id_seq'::regclass::oid)::text")
        self.helper('backup_configured_database')
        self.assertEqual(self.query(self.database, "SELECT row('retained'::regclass::oid, 'retained_id_seq'::regclass::oid)::text"), original_objects)
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained', 'af_app'), 'before')
        self.query(self.database, "ALTER TABLE retained ADD COLUMN migrated integer; UPDATE retained SET value='after'", 'af_app')
        self.helper('restore_configured_database')
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained', 'af_app'), 'before')
        self.assertEqual(self.query(self.database, "SELECT count(*) FROM information_schema.columns "
                                    "WHERE table_name='retained' AND column_name='migrated'"), '0')
        self.assertEqual(self.query(self.database, 'SELECT nextval(\'retained_id_seq\')', 'af_app'), '2')
        self.assert_identity_preserved()

    def test_migration_only_objects_and_schemas_are_removed(self):
        self.helper('backup_configured_database', backend='pgsql')
        self.query(self.database, 'CREATE TABLE migration_only(value integer); CREATE SCHEMA migration_only_schema; '
                   'CREATE TABLE migration_only_schema.extra(value text); CREATE SEQUENCE migration_sequence; '
                   "CREATE FUNCTION migration_function() RETURNS integer LANGUAGE sql AS 'SELECT 1'; "
                   "CREATE TYPE migration_type AS ENUM ('added')", 'af_app')
        self.helper('restore_configured_database', backend='pgsql')
        self.assertEqual(self.query(self.database, "SELECT to_regclass('migration_only') IS NULL AND "
                                    "to_regclass('migration_sequence') IS NULL AND "
                                    "to_regprocedure('migration_function()') IS NULL AND "
                                    "to_regtype('migration_type') IS NULL AND NOT EXISTS "
                                    "(SELECT FROM pg_namespace WHERE nspname='migration_only_schema')"), 't')
        self.assert_identity_preserved()

    def test_quoted_application_owner_cannot_break_identity_guard(self):
        owner = 'af_$af_identity$_owner'
        self.query('postgres', f'ALTER DATABASE {self.database} OWNER TO "{owner}"')
        self.query(self.database, f'ALTER TABLE retained OWNER TO "{owner}"')
        self.helper('backup_configured_database', username=owner)
        self.query(self.database, "UPDATE retained SET value='after'", owner)
        self.helper('restore_configured_database', username=owner)
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained', owner), 'before')
        self.assert_identity_preserved()

    def test_failed_restore_rolls_back_cleanup_data_and_sequence_changes(self):
        self.helper('backup_configured_database')
        self.query(self.database, "UPDATE retained SET value='failed-migration'; "
                   "INSERT INTO retained(value) VALUES ('new-row'); CREATE TABLE migration_only(value integer); "
                   'INSERT INTO migration_only VALUES (41)', 'af_app')
        with (self.backup / 'database.sql').open('a') as output:
            output.write('\nSELECT 1 / 0;\n')
        result = self.helper('restore_configured_database', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('not committed', result.stderr)
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained ORDER BY id', 'af_app'), 'failed-migration\nnew-row')
        self.assertEqual(self.query(self.database, 'SELECT value FROM migration_only', 'af_app'), '41')
        self.assertEqual(self.query(self.database, "SELECT nextval('retained_id_seq')", 'af_app'), '3')
        self.assert_identity_preserved()

    def test_foreign_owned_objects_fail_preflight_without_publishing_ready_marker(self):
        self.query(self.database, 'CREATE TABLE foreign_owned(value text); ALTER TABLE foreign_owned OWNER TO af_foreign_owner; '
                   "INSERT INTO foreign_owned VALUES ('protected'); GRANT SELECT ON foreign_owned TO af_app")
        result = self.helper('backup_configured_database', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.backup / '.af-database-ready').exists())
        self.assertEqual(self.query(self.database, 'SELECT value FROM foreign_owned'), 'protected')
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained'), 'before')
        self.assert_identity_preserved()

    def test_non_owner_fails_preflight_without_mutating_database(self):
        self.query(self.database, 'GRANT USAGE ON SCHEMA public TO af_reader; '
                   'GRANT SELECT ON ALL TABLES IN SCHEMA public TO af_reader; '
                   'GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO af_reader', 'af_app')
        result = self.helper('backup_configured_database', username='af_reader', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.backup / '.af-database-ready').exists())
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained'), 'before')

    def test_extension_schema_owners_acls_and_default_privileges_are_preserved(self):
        if self.query(self.database, "SELECT count(*) FROM pg_available_extensions WHERE name='pgcrypto'") != '1':
            self.skipTest('Trusted pgcrypto extension is not installed')
        self.query(self.database, 'CREATE EXTENSION pgcrypto; CREATE SCHEMA operator_schema; '
                   'CREATE TABLE operator_schema.owned(value integer); '
                   'GRANT USAGE ON SCHEMA operator_schema TO af_reader; GRANT SELECT ON operator_schema.owned TO af_reader; '
                   'ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO af_reader; '
                   'ALTER DEFAULT PRIVILEGES REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC', 'af_app')
        extension = self.query(self.database, "SELECT row(extname, extversion, extowner, nspname)::text "
                               "FROM pg_extension JOIN pg_namespace ON extnamespace=pg_namespace.oid WHERE extname='pgcrypto'")
        privileges = self.query(self.database, 'SELECT row(defaclrole, defaclobjtype, defaclacl)::text '
                                'FROM pg_default_acl WHERE defaclnamespace=0 ORDER BY defaclobjtype')
        self.helper('backup_configured_database')
        self.assertEqual(self.query(self.database, 'SELECT row(defaclrole, defaclobjtype, defaclacl)::text '
                                    'FROM pg_default_acl WHERE defaclnamespace=0 ORDER BY defaclobjtype'), privileges)
        self.query(self.database, 'REVOKE SELECT ON operator_schema.owned FROM af_reader; '
                   'ALTER DEFAULT PRIVILEGES GRANT INSERT ON TABLES TO af_migration_reader; '
                   'CREATE TABLE migration_only(value integer); DROP EXTENSION pgcrypto', 'af_app')
        self.helper('restore_configured_database')
        self.assertEqual(self.query(self.database, "SELECT row(extname, extversion, extowner, nspname)::text "
                                    "FROM pg_extension JOIN pg_namespace ON extnamespace=pg_namespace.oid WHERE extname='pgcrypto'"), extension)
        self.assertEqual(self.query(self.database, "SELECT pg_get_userbyid(relowner) FROM pg_class "
                                    "WHERE oid='operator_schema.owned'::regclass"), 'af_app')
        self.assertEqual(self.query(self.database, "SELECT has_table_privilege('af_reader', 'operator_schema.owned', 'SELECT')"), 't')
        self.assertEqual(self.query(self.database, 'SELECT row(defaclrole, defaclobjtype, defaclacl)::text '
                                    'FROM pg_default_acl WHERE defaclnamespace=0 ORDER BY defaclobjtype'), privileges)

    def test_unrestorable_extension_owner_is_detected_before_migrations(self):
        if self.query(self.database, "SELECT count(*) FROM pg_available_extensions WHERE name='pgcrypto'") != '1':
            self.skipTest('pgcrypto extension is not installed')
        self.query(self.database, 'CREATE EXTENSION pgcrypto')
        result = self.helper('backup_configured_database', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.backup / '.af-database-ready').exists())
        self.assertEqual(self.query(self.database, "SELECT count(*) FROM pg_extension WHERE extname='pgcrypto'"), '1')
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained'), 'before')

    def test_nondefault_extension_version_fails_preflight_without_changing_it(self):
        extension = self.query(self.database, "SELECT versions.name || '|' || versions.version "
                               "FROM pg_available_extension_versions AS versions JOIN pg_available_extensions AS defaults "
                               "USING (name) WHERE name IN ('pgcrypto', 'citext', 'hstore', 'pg_trgm') "
                               "AND versions.trusted AND versions.version <> defaults.default_version ORDER BY name, version LIMIT 1")
        if not extension:
            self.skipTest('No nondefault trusted extension version is installed')
        name, version = extension.split('|')
        self.query(self.database, f"CREATE EXTENSION {name} VERSION '{version}'", 'af_app')
        result = self.helper('backup_configured_database', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.backup / '.af-database-ready').exists())
        self.assertEqual(self.query(self.database, f"SELECT extversion FROM pg_extension WHERE extname='{name}'"), version)
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained'), 'before')

    def test_database_acl_comment_and_settings_are_restored_without_global_changes(self):
        self.query(self.database, f'REVOKE TEMPORARY ON DATABASE {self.database} FROM PUBLIC; '
                   f'GRANT CONNECT ON DATABASE {self.database} TO af_reader; '
                   f"COMMENT ON DATABASE {self.database} IS 'original comment'; "
                   f"ALTER DATABASE {self.database} SET search_path TO operator_schema, public; "
                   f"ALTER ROLE af_app IN DATABASE {self.database} SET work_mem TO '16MB'", 'af_app')
        original = self.query('postgres', f"SELECT row(datacl, datconnlimit, shobj_description(oid, 'pg_database'))::text "
                              f"FROM pg_database WHERE datname='{self.database}'")
        settings = self.query('postgres', f"SELECT row(setrole, setconfig)::text FROM pg_db_role_setting "
                              f"WHERE setdatabase=(SELECT oid FROM pg_database WHERE datname='{self.database}') ORDER BY setrole")
        self.helper('backup_configured_database')
        self.query(self.database, f'GRANT TEMPORARY ON DATABASE {self.database} TO af_migration_reader; '
                   f"COMMENT ON DATABASE {self.database} IS 'migrated'; "
                   f'ALTER DATABASE {self.database} CONNECTION LIMIT 4; '
                   f"ALTER DATABASE {self.database} SET work_mem TO '32MB'; "
                   f"ALTER ROLE af_app IN DATABASE {self.database} SET work_mem TO '64MB'", 'af_app')
        self.helper('restore_configured_database')
        self.assertEqual(self.query('postgres', f"SELECT row(datacl, datconnlimit, shobj_description(oid, 'pg_database'))::text "
                                    f"FROM pg_database WHERE datname='{self.database}'"), original)
        self.assertEqual(self.query('postgres', f"SELECT row(setrole, setconfig)::text FROM pg_db_role_setting "
                                    f"WHERE setdatabase=(SELECT oid FROM pg_database WHERE datname='{self.database}') ORDER BY setrole"), settings)

    def test_large_objects_are_restored_and_migration_only_large_objects_removed(self):
        original = self.query(self.database, "SELECT lo_from_bytea(0, convert_to('original', 'UTF8'))", 'af_app')
        self.helper('backup_configured_database')
        added = self.query(self.database, "SELECT lo_from_bytea(0, convert_to('new', 'UTF8'))", 'af_app')
        self.query(self.database, f"SELECT lo_put({original}, 0, convert_to('modified', 'UTF8'))", 'af_app')
        self.helper('restore_configured_database')
        self.assertEqual(self.query(self.database, f"SELECT convert_from(lo_get({original}), 'UTF8')", 'af_app'), 'original')
        self.assertEqual(self.query(self.database, f'SELECT count(*) FROM pg_largeobject_metadata WHERE oid={added}'), '0')

    def test_backup_and_restore_keep_credentials_off_argv_and_public_logs(self):
        self.helper('backup_configured_database')
        self.helper('restore_configured_database')
        commands = (self.workspace / 'commands.jsonl').read_text()
        self.assertNotIn(PASSWORD, commands)
        self.assertNotIn(PASSWORD, (self.workspace / 'application.log').read_text())
        self.assertNotIn(PASSWORD, (self.backup / 'postgres-recovery.log').read_text())
        self.assertEqual(self.backup.stat().st_mode & 0o777, 0o700)
        for artifact in self.backup.iterdir():
            self.assertEqual(artifact.stat().st_mode & 0o777, 0o600, str(artifact))
            if artifact.suffix == '.sql':
                self.assertNotRegex(artifact.read_text(), r'(?im)^\s*(?:CREATE|DROP)\s+DATABASE\b|\bDROP\s+OWNED\b')
        for command in map(json.loads, commands.splitlines()):
            if command[0] == 'pg_dump':
                self.assertNotIn('--create', command)
                self.assertNotIn('--no-owner', command)
                self.assertNotIn('--no-acl', command)
            else:
                self.assertIn('--no-psqlrc', command)
                self.assertIn('--dbname=configured_app', command)

    def test_legacy_destructive_dump_and_missing_artifacts_fail_closed(self):
        self.helper('backup_configured_database')
        (self.backup / '.af-postgres-ready').unlink()
        (self.backup / 'database.sql').write_text('DROP DATABASE configured_app;')
        result = self.helper('restore_configured_database', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained'), 'before')
        self.assert_identity_preserved()

    def test_empty_private_log_does_not_disable_valid_recovery(self):
        self.helper('backup_configured_database')
        (self.backup / 'postgres-recovery.log').write_text('')
        self.query(self.database, "UPDATE retained SET value='after'", 'af_app')
        self.helper('restore_configured_database')
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained'), 'before')

    def test_psql_startup_commands_cannot_bypass_recovery_transaction(self):
        startup = self.workspace / 'psqlrc'
        startup.write_text('\\quit 7\n')
        self.helper_environment['PSQLRC'] = str(startup)
        self.helper('backup_configured_database')
        self.query(self.database, "UPDATE retained SET value='after'", 'af_app')
        self.helper('restore_configured_database')
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained'), 'before')

    def test_replaced_database_identity_is_rejected_before_cleanup(self):
        self.helper('backup_configured_database')
        self.query('postgres', f'DROP DATABASE {self.database};')
        self.query('postgres', f'CREATE DATABASE {self.database} OWNER af_app')
        self.query(self.database, "CREATE TABLE retained(value text); INSERT INTO retained VALUES ('replacement')", 'af_app')
        result = self.helper('restore_configured_database', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained'), 'replacement')

    def test_public_schema_absence_and_quoted_custom_schema_survive_recovery(self):
        self.query(self.database, 'DROP SCHEMA public CASCADE; CREATE SCHEMA "operator \'quoted\' schema"; '
                   'CREATE TABLE "operator \'quoted\' schema".retained(value text); '
                   "INSERT INTO \"operator 'quoted' schema\".retained VALUES ('before')", 'af_app')
        self.helper('backup_configured_database')
        self.query(self.database, 'CREATE SCHEMA public; CREATE TABLE public.migration_only(value text)', 'af_app')
        self.helper('restore_configured_database')
        self.assertEqual(self.query(self.database, "SELECT count(*) FROM pg_namespace WHERE nspname='public'"), '0')
        self.assertEqual(self.query(self.database, 'SELECT value FROM "operator \'quoted\' schema".retained', 'af_app'), 'before')

    def test_symlinked_artifacts_and_mismatched_database_names_are_rejected(self):
        self.helper('backup_configured_database')
        result = self.helper('restore_configured_database', database='unrelated_app', check=False)
        self.assertNotEqual(result.returncode, 0)
        original = self.workspace / 'original-dump.sql'
        (self.backup / 'database.sql').rename(original)
        (self.backup / 'database.sql').symlink_to(original)
        result = self.helper('restore_configured_database', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.query(self.database, 'SELECT value FROM retained'), 'before')

    def test_unsafe_database_name_and_symlinked_backup_parent_are_rejected(self):
        result = self.helper('backup_configured_database', database='configured_app; DROP DATABASE unrelated_app', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.backup.exists())
        parent = self.workspace / 'linked'
        parent.symlink_to(self.workspace, target_is_directory=True)
        result = self.helper('backup_configured_database', backup=parent / 'backup', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.backup.exists())


class ConfiguredLocalDatabaseHelpers(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='af-configured-local-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.backup = self.root / 'backup'
        self.database = self.root / 'application.db'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.environment = {**os.environ, 'AF_TEST_PASSWORD': PASSWORD, 'AF_TEST_ROOT': str(self.root),
                            'PATH': str(self.bin) + os.pathsep + os.environ['PATH']}

    def helper(self, operation, backend, *, check=True):
        program = HELPERS + '''
print_error() { printf '%s\\n' "$*" >&2; }
print_warn() { printf '%s\\n' "$*" >&2; }
LOGFILE="$2/application.log"
"$1" "$2/backup" "$3" configured_app db.example:5432 af_app "$AF_TEST_PASSWORD" "$2/application.db"
'''
        result = subprocess.run(['bash', '-euc', program, 'fixture', operation, str(self.root), backend],
                                env=self.environment, capture_output=True, text=True, timeout=20)
        if check:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def test_mysql_and_mariadb_keep_existing_dump_restore_contract(self):
        wrapper = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
root = Path(os.environ['AF_TEST_ROOT'])
with (root / 'commands.jsonl').open('a') as output:
    output.write(json.dumps({'arguments': [Path(sys.argv[0]).name, *sys.argv[1:]],
                             'password_available': bool(os.environ.get('MYSQL_PWD'))}) + '\\n')
if Path(sys.argv[0]).name == 'mysqldump':
    if os.environ.get('AF_TEST_DUMP_FAIL'):
        sys.exit(71)
    print((root / 'database-state').read_text(), end='')
else:
    (root / 'database-state').write_text(sys.stdin.read())
'''
        for command in ('mysqldump', 'mysql'):
            executable = self.bin / command
            executable.write_text(wrapper)
            executable.chmod(0o700)
        for backend in ('mysql', 'mariadb'):
            with self.subTest(backend=backend):
                if self.backup.exists():
                    shutil.rmtree(self.backup)
                state = self.root / 'database-state'
                state.write_text('original schema and data\n')
                self.helper('backup_configured_database', backend)
                state.write_text('migrated schema\n')
                self.helper('restore_configured_database', backend)
                self.assertEqual(state.read_text(), 'original schema and data\n')
        commands = [json.loads(line) for line in (self.root / 'commands.jsonl').read_text().splitlines()]
        self.assertNotIn(PASSWORD, json.dumps(commands))
        for command in commands:
            self.assertTrue(command['password_available'])
            if command['arguments'][0] == 'mysqldump':
                self.assertIn('--single-transaction', command['arguments'])
                self.assertIn('--add-drop-database', command['arguments'])
                self.assertIn('--databases', command['arguments'])
        shutil.rmtree(self.backup)
        self.environment['AF_TEST_DUMP_FAIL'] = '1'
        self.assertNotEqual(self.helper('backup_configured_database', 'mysql', check=False).returncode, 0)
        self.assertFalse((self.backup / '.af-database-ready').exists())

    def test_sqlite_restores_real_database_and_removes_migration_only_sidecars(self):
        for backend in ('sqlite', 'sqlite3'):
            with self.subTest(backend=backend):
                if self.backup.exists():
                    shutil.rmtree(self.backup)
                with sqlite3.connect(self.database) as database:
                    database.execute('CREATE TABLE IF NOT EXISTS retained(value text)')
                    database.execute('DELETE FROM retained')
                    database.execute("INSERT INTO retained VALUES ('before')")
                self.helper('backup_configured_database', backend)
                with sqlite3.connect(self.database) as database:
                    database.execute("UPDATE retained SET value='after'")
                    database.execute('CREATE TABLE migration_only(value integer)')
                for suffix in ('-wal', '-shm'):
                    Path(str(self.database) + suffix).write_text('new sidecar')
                self.helper('restore_configured_database', backend)
                for suffix in ('-wal', '-shm'):
                    self.assertFalse(Path(str(self.database) + suffix).exists())
                with sqlite3.connect(self.database) as database:
                    self.assertEqual(database.execute('SELECT value FROM retained').fetchone()[0], 'before')
                    self.assertIsNone(database.execute("SELECT name FROM sqlite_master WHERE name='migration_only'").fetchone())


if __name__ == '__main__':
    unittest.main()
