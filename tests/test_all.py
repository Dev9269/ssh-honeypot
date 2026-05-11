import pytest
import sys
import os
import tempfile
import json
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
# Set test config before importing modules
os.environ['HONEYPOT_CONFIG'] = 'test'


@pytest.fixture(autouse=True)
def setup_test_env():
    with tempfile.TemporaryDirectory() as tmpdir:
        old_cwd = os.getcwd()
        os.chdir(tmpdir)
        os.makedirs('logs', exist_ok=True)
        os.makedirs('honeypot', exist_ok=True)
        yield
        import logging
        from honeypot import logger as logger_mod
        logger_mod.reset_logger()
        os.chdir(old_cwd)


class TestConfig:
    def test_default_values(self):
        from honeypot import config
        assert config.PORT == 2222
        assert config.HOST == '0.0.0.0'
        assert config.AUTH_DELAY == 2
        assert config.SHELL_ENABLED == True
        assert config.DB_ENABLED == True
        assert config.GEO_ENABLED == True
        assert config.MITRE_ENABLED == True
        assert config.RATE_LIMIT_MAX_CONNECTIONS == 10
        assert config.RATE_LIMIT_WINDOW == 60

    def test_yaml_loading(self):
        from honeypot import config
        yaml_path = os.path.join(os.path.dirname(__file__), '..', 'honeypot.yaml')
        assert os.path.exists(yaml_path)
        result = config.load_yaml_config(yaml_path)
        assert result == True
        assert config.PORT == 2222
        assert config.SHELL_ENABLED == True

    def test_yaml_not_found(self):
        from honeypot import config
        result = config.load_yaml_config('/nonexistent/config.yaml')
        assert result == False


class TestDatabase:
    @pytest.fixture(autouse=True)

    def setup_db(self):
        from honeypot import config
        config.DB_PATH = ':memory:'
        config.LOG_DIR = '.'
        from honeypot import db
        db.init_db()
        yield
        if hasattr(db, '_local'):
            try:
                db._local.conn.close()
            except:
                pass

    def test_insert_auth_attempt(self, setup_db):
        from honeypot import db
        db.insert_auth_attempt('192.168.1.1', 'root', 'password123', 'password')
        stats = db.get_stats()
        assert stats['total_attempts'] >= 1

    def test_insert_command(self, setup_db):
        from honeypot import db
        db.insert_command('192.168.1.1', 'root', 'whoami', 'root\r\n')
        stats = db.get_stats()

    def test_block_ip(self, setup_db):
        from honeypot import db
        db.block_ip('10.0.0.5', reason='rate_limit', duration=60)
        assert db.is_ip_blocked('10.0.0.5') == True

    def test_block_ip_expired(self, setup_db):
        from honeypot import db
        db.block_ip('10.0.0.6', reason='test', duration=-1)
        assert db.is_ip_blocked('10.0.0.6') == False

    def test_permanent_block(self, setup_db):
        from honeypot import db
        db.block_ip('10.0.0.7', reason='permanent', duration=0)
        assert db.is_ip_blocked('10.0.0.7') == True

    def test_block_unblock(self, setup_db):
        from honeypot import db
        db.block_ip('192.168.1.99', reason='test', duration=1)
        assert db.is_ip_blocked('192.168.1.99') == True
        time.sleep(1.1)
        assert db.is_ip_blocked('192.168.1.99') == False

    def test_connection_tracking(self, setup_db):
        from honeypot import db
        conn_id = db.insert_connection('192.168.1.1', 2222)
        assert conn_id is not None
        db.update_connection_end(conn_id, 12.5)

    def test_get_stats_empty(self, setup_db):
        from honeypot import db
        stats = db.get_stats()
        assert 'total_attempts' in stats
        assert 'unique_ips' in stats
        assert 'top_usernames' in stats
        assert 'top_passwords' in stats
        assert 'top_ips' in stats
        assert 'recent' in stats


class TestRateLimiter:

    def test_basic_rate_limit(self):
        from honeypot import config
        config.RATE_LIMIT_MAX_CONNECTIONS = 3
        config.RATE_LIMIT_WINDOW = 60
        config.RATE_LIMIT_BAN_DURATION = 5

        from honeypot import ratelimiter
        limiter = ratelimiter.RateLimiter()
        assert limiter.is_allowed('10.0.0.1') == True
        assert limiter.is_allowed('10.0.0.1') == True
        assert limiter.is_allowed('10.0.0.1') == True
        assert limiter.is_allowed('10.0.0.1') == False

    def test_rate_limit_reset(self):
        from honeypot import config
        config.RATE_LIMIT_MAX_CONNECTIONS = 1
        config.RATE_LIMIT_WINDOW = 60

        from honeypot import ratelimiter
        limiter = ratelimiter.RateLimiter()
        limiter.is_allowed('10.0.0.2')
        limiter.reset('10.0.0.2')
        assert limiter.is_allowed('10.0.0.2') == True

    def test_multiple_ips_independent(self):
        from honeypot import config
        config.RATE_LIMIT_MAX_CONNECTIONS = 2
        config.RATE_LIMIT_WINDOW = 60

        from honeypot import ratelimiter
        limiter = ratelimiter.RateLimiter()
        assert limiter.is_allowed('10.0.0.3') == True
        assert limiter.is_allowed('10.0.0.3') == True
        assert limiter.is_allowed('10.0.0.4') == True
        assert limiter.is_allowed('10.0.0.3') == False
        assert limiter.is_allowed('10.0.0.4') == True

    def test_remaining_count(self):
        from honeypot import config
        config.RATE_LIMIT_MAX_CONNECTIONS = 5
        config.RATE_LIMIT_WINDOW = 60

        from honeypot import ratelimiter
        limiter = ratelimiter.RateLimiter()
        assert limiter.get_remaining('10.0.0.5') == 5
        limiter.is_allowed('10.0.0.5')
        assert limiter.get_remaining('10.0.0.5') == 4
        for _ in range(4):
            limiter.is_allowed('10.0.0.5')
        assert limiter.get_remaining('10.0.0.5') == 0


class TestAnalyzer:

    def test_mitre_techniques_password(self):
        from honeypot import analyzer
        mitre = analyzer.MitreAnalyzer()
        techs = mitre.analyze_auth_attempt('root', 'password')
        assert len(techs) >= 1
        assert 'T1110' in str(techs)

    def test_mitre_techniques_publickey(self):
        from honeypot import analyzer
        mitre = analyzer.MitreAnalyzer()
        techs = mitre.analyze_auth_attempt('root', 'publickey')
        assert len(techs) >= 1
        assert 'T1098' in str(techs)

    def test_mitre_command_recon(self):
        from honeypot import analyzer
        mitre = analyzer.MitreAnalyzer()
        techs = mitre.analyze_command('whoami')
        ids = [t['id'] for t in techs]
        assert 'T1059' in ids
        assert 'T1046' in ids

    def test_mitre_command_lateral(self):
        from honeypot import analyzer
        mitre = analyzer.MitreAnalyzer()
        techs = mitre.analyze_command('ssh root@10.0.0.5')
        ids = [t['id'] for t in techs]
        assert 'T1059' in ids
        assert 'T1021' in ids

    def test_mitre_command_escalation(self):
        from honeypot import analyzer
        mitre = analyzer.MitreAnalyzer()
        techs = mitre.analyze_command('sudo su -')
        ids = [t['id'] for t in techs]
        assert 'T1059' in ids
        assert 'T1068' in ids

    def test_mitre_format(self):
        from honeypot import analyzer
        mitre = analyzer.MitreAnalyzer()
        techs = [{'id': 'T1110', 'name': 'Brute Force'}]
        result = mitre.format_techniques(techs)
        assert result == 'T1110:Brute Force'

    def test_mitre_format_empty(self):
        from honeypot import analyzer
        mitre = analyzer.MitreAnalyzer()
        assert mitre.format_techniques([]) == ''


class TestShell:

    def test_whoami(self):
        from honeypot import shell
        resp = shell.handle_command('whoami', '10.0.0.1', 'root')
        assert 'root' in resp

    def test_id(self):
        from honeypot import shell
        resp = shell.handle_command('id', '10.0.0.1', 'root')
        assert 'uid=0' in resp

    def test_cat_file(self):
        from honeypot import shell
        resp = shell.handle_command('cat /etc/hostname', '10.0.0.1', 'root')
        assert len(resp) > 0

    def test_cat_nonexistent(self):
        from honeypot import shell
        resp = shell.handle_command('cat /nonexistent/file', '10.0.0.1', 'root')
        assert 'No such file' in resp

    def test_ls_root(self):
        from honeypot import shell
        resp = shell.handle_command('ls /', '10.0.0.1', 'root')
        assert 'bin' in resp
        assert 'etc' in resp
        assert 'home' in resp

    def test_ls_no_args(self):
        from honeypot import shell
        resp = shell.handle_command('ls', '10.0.0.1', 'root')
        assert resp is not None

    def test_unknown_command(self):
        from honeypot import shell
        resp = shell.handle_command('foobarbaz123', '10.0.0.1', 'root')
        assert 'command not found' in resp

    def test_exit(self):
        from honeypot import shell
        resp = shell.handle_command('exit', '10.0.0.1', 'root')
        assert 'logout' in resp

    def test_echo(self):
        from honeypot import shell
        resp = shell.handle_command('echo hello world', '10.0.0.1', 'root')
        assert resp.strip() == 'hello world'

    def test_empty_command(self):
        from honeypot import shell
        resp = shell.handle_command('', '10.0.0.1', 'root')
        assert resp == ''

    def test_prompt_format(self):
        from honeypot import shell
        prompt = shell.get_prompt('root')
        assert prompt.startswith('root@')

    def test_df_h(self):
        from honeypot import shell
        resp = shell.handle_command('df -h', '10.0.0.1', 'root')
        assert 'Filesystem' in resp
        assert '/dev/sda1' in resp

    def test_free_m(self):
        from honeypot import shell
        resp = shell.handle_command('free -m', '10.0.0.1', 'root')
        assert 'Mem:' in resp

    def test_uname(self):
        from honeypot import shell
        resp = shell.handle_command('uname -a', '10.0.0.1', 'root')
        assert 'Linux' in resp

    def test_ifconfig(self):
        from honeypot import shell
        resp = shell.handle_command('ifconfig', '10.0.0.1', 'root')
        assert 'eth0' in resp or 'inet' in resp


class TestLogger:
    @pytest.fixture(autouse=True)

    def setup_logger(self):
        from honeypot import logger as logger_mod
        logger_mod.reset_logger()
        from honeypot import config
        config.LOG_DIR = 'test_logs'
        config.LOG_FILE = os.path.join('test_logs', 'attacks.log')
        config.JSON_LOG_FILE = os.path.join('test_logs', 'attacks.json')
        yield
        logger_mod.reset_logger()

    def test_log_auth_attempt(self, setup_logger):
        from honeypot import config
        config.LOG_ROTATION_ENABLED = False
        from honeypot import logger
        log = logger.HoneypotLogger()
        log.log_attempt('192.168.1.1', 'root', 'toor', 'password')
        assert os.path.exists(config.LOG_FILE)
        assert os.path.exists(config.JSON_LOG_FILE)

    def test_log_with_mitre(self, setup_logger):
        from honeypot import config
        config.LOG_ROTATION_ENABLED = False
        from honeypot import logger
        log = logger.HoneypotLogger()
        log.log_attempt('10.0.0.1', 'admin', 'admin123', 'password', mitre='T1110:Brute Force')
        with open(config.LOG_FILE, 'r') as f:
            content = f.read()
        assert 'T1110' in content

    def test_json_format(self, setup_logger):
        from honeypot import config
        config.LOG_ROTATION_ENABLED = False
        from honeypot import logger
        log = logger.HoneypotLogger()
        log.log_attempt('192.168.1.1', 'root', 'toor', 'password')
        with open(config.JSON_LOG_FILE, 'r') as f:
            data = json.load(f)
        assert len(data) >= 1
        assert data[-1]['ip'] == '192.168.1.1'
        assert data[-1]['event'] == 'auth_attempt'

    def test_log_rotation(self, setup_logger):
        from honeypot import config
        config.LOG_ROTATION_ENABLED = True
        config.LOG_MAX_SIZE_MB = 1
        config.LOG_BACKUP_COUNT = 3
        from honeypot import logger
        log = logger.HoneypotLogger()
        for i in range(10):
            log.log_attempt(f'10.0.0.{i}', f'user{i}', f'pass{i}', 'password')

    def test_session_activity(self, setup_logger):
        from honeypot import config
        config.LOG_ROTATION_ENABLED = False
        from honeypot import logger
        log = logger.HoneypotLogger()
        log.log_session_activity('192.168.1.1', 'connected')
        with open(config.JSON_LOG_FILE, 'r') as f:
            data = json.load(f)
        assert any(e['event'] == 'session_activity' for e in data)


class TestIPFilter:

    def test_ip_in_cidr(self):
        from honeypot.server import _ip_in_cidrs
        assert _ip_in_cidrs('10.0.0.5', ['10.0.0.0/8']) == True
        assert _ip_in_cidrs('192.168.1.1', ['10.0.0.0/8']) == False
        assert _ip_in_cidrs('invalid', ['10.0.0.0/8']) == False
        assert _ip_in_cidrs('192.168.1.1', ['192.168.1.0/24']) == True

    def test_ip_allowed_whitelist(self):
        from honeypot import config
        config.WHITELIST = ['10.0.0.0/8']
        config.BLACKLIST = []
        from honeypot.server import _is_ip_allowed
        assert _is_ip_allowed('10.0.0.5') == True
        assert _is_ip_allowed('192.168.1.1') == False

    def test_ip_allowed_blacklist(self):
        from honeypot import config
        config.WHITELIST = []
        config.BLACKLIST = ['192.168.1.0/24']
        from honeypot.server import _is_ip_allowed
        assert _is_ip_allowed('10.0.0.5') == True
        assert _is_ip_allowed('192.168.1.1') == False

    def test_ip_allowed_no_filter(self):
        from honeypot import config
        config.WHITELIST = []
        config.BLACKLIST = []
        from honeypot.server import _is_ip_allowed
        assert _is_ip_allowed('10.0.0.5') == True
        assert _is_ip_allowed('0.0.0.0') == True


class TestGeo:

    def test_geo_lookup_online(self):
        from honeypot import geo
        geo_instance = geo.GeoIP()
        result = geo_instance.lookup_online('8.8.8.8')
        assert isinstance(result, dict)
        assert 'country' in result
        assert 'city' in result

    def test_geo_lookup_invalid_ip(self):
        from honeypot import geo
        geo_instance = geo.GeoIP()
        result = geo_instance.lookup('invalid')
        assert result['country'] == ''


class TestIntel:

    def test_severity_mapping(self):
        from honeypot import intel
        intel_instance = intel.ThreatIntel()
        assert intel_instance.get_severity(8) == 'critical'
        assert intel_instance.get_severity(6) == 'high'
        assert intel_instance.get_severity(4) == 'low'
        assert intel_instance.get_severity(2) == 'low'
        assert intel_instance.get_severity(0) == 'info'


class TestAlerts:

    def test_should_alert_min_severity(self):
        from honeypot import config
        config.ALERT_ENABLED = True
        config.ALERT_MIN_SEVERITY = 'low'
        config.ALERT_WEBHOOK_URL = ''
        from honeypot.alerts import AlertManager
        alerts = AlertManager()
        alerts.send_alert('test', 'test message', 'low')
        alerts.send_alert('test', 'test message', 'critical')

    def test_alert_disabled(self):
        from honeypot import config
        config.ALERT_ENABLED = False
        from honeypot.alerts import AlertManager
        alerts = AlertManager()
        alerts.send_alert('test', 'test msg', 'critical')


class TestStress:

    def test_many_rate_limiter_ops(self):
        from honeypot import config
        config.RATE_LIMIT_MAX_CONNECTIONS = 100
        config.RATE_LIMIT_WINDOW = 60
        from honeypot import ratelimiter
        limiter = ratelimiter.RateLimiter()
        results = [limiter.is_allowed(f'10.0.0.{i % 10}') for i in range(1000)]
        assert sum(results) > 900

    def test_many_db_inserts(self):
        import tempfile
        tmp = tempfile.mktemp(suffix='.db')
        from honeypot import config
        config.DB_PATH = tmp
        config.LOG_DIR = '.'
        from honeypot import db
        db.init_db()
        for i in range(500):
            db.insert_auth_attempt(f'10.0.0.{i % 50}', f'user{i}', f'pass{i}', 'password')
        stats = db.get_stats()
        assert stats['total_attempts'] == 500
        assert stats['unique_ips'] == 50

    def test_many_shell_commands(self):
        from honeypot import logger as logger_mod
        logger_mod.reset_logger()
        from honeypot import shell
        commands = ['whoami', 'id', 'pwd', 'ls', 'ls /', 'cat /etc/passwd', 'uname -a',
                    'df -h', 'free -m', 'ps aux', 'ifconfig', 'env', 'echo test',
                    'cd /tmp', 'ping google.com', 'foobarz', 'exit'] * 5
        for cmd in commands:
            shell.handle_command(cmd, 'stress.test', 'root')

    def test_many_log_entries(self):
        import logging
        for h in logging.getLogger('honeypot_file_logger').handlers[:]:
            logging.getLogger('honeypot_file_logger').removeHandler(h)
        logging.getLogger('honeypot_file_logger').handlers.clear()
        from honeypot import logger as logger_mod
        logger_mod._default_logger = None

        from honeypot import config
        config.LOG_ROTATION_ENABLED = True
        config.LOG_MAX_SIZE_MB = 1
        config.LOG_BACKUP_COUNT = 2
        import tempfile
        tmpdir = tempfile.mkdtemp()
        config.LOG_DIR = tmpdir
        config.LOG_FILE = os.path.join(tmpdir, 'attacks.log')
        config.JSON_LOG_FILE = os.path.join(tmpdir, 'attacks.json')
        from honeypot import logger
        log = logger.HoneypotLogger()
        for i in range(100):
            log.log_attempt(f'10.0.0.{i % 10}', f'user{i}', f'pass{i}', 'password')

    def test_concurrent_rate_limiter(self):
        from honeypot import config
        config.RATE_LIMIT_MAX_CONNECTIONS = 50
        config.RATE_LIMIT_WINDOW = 60
        import threading
        from honeypot import ratelimiter
        limiter = ratelimiter.RateLimiter()
        results = []

        def worker():
            for _ in range(100):
                results.append(limiter.is_allowed('10.0.0.1'))
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
