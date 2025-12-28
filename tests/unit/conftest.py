"""
Unit test fixtures for potsnitch.
"""

import pytest
from unittest.mock import MagicMock, patch


# Socket fixtures
@pytest.fixture
def mock_socket():
    """Patches socket.socket for testing network operations."""
    with patch("socket.socket") as mock:
        socket_instance = MagicMock()
        mock.return_value = socket_instance
        yield mock


# SSH/Paramiko fixtures
@pytest.fixture
def mock_paramiko():
    """Patches paramiko.SSHClient for testing SSH operations."""
    with patch("paramiko.SSHClient") as mock:
        ssh_instance = MagicMock()
        mock.return_value = ssh_instance
        yield mock


# Redis fixtures
@pytest.fixture
def mock_redis():
    """Patches redis.Redis for testing Redis operations."""
    with patch("redis.Redis") as mock:
        redis_instance = MagicMock()
        mock.return_value = redis_instance
        yield mock


# MongoDB fixtures
@pytest.fixture
def mock_pymongo():
    """Patches pymongo.MongoClient for testing MongoDB operations."""
    with patch("pymongo.MongoClient") as mock:
        mongo_instance = MagicMock()
        mock.return_value = mongo_instance
        yield mock


# MySQL fixtures
@pytest.fixture
def mock_mysql():
    """Patches mysql.connector for testing MySQL operations."""
    with patch("mysql.connector") as mock:
        yield mock


# PostgreSQL fixtures
@pytest.fixture
def mock_psycopg2():
    """Patches psycopg2 for testing PostgreSQL operations."""
    with patch("psycopg2") as mock:
        yield mock


# Sample data fixtures
@pytest.fixture
def sample_ssh_banner():
    """Returns a sample Cowrie SSH honeypot banner."""
    return b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2\r\n"


@pytest.fixture
def sample_mysql_handshake():
    """Returns a sample MySQL handshake packet."""
    # MySQL protocol handshake packet structure
    # Length (3 bytes) + Sequence ID (1 byte) + Protocol version + Server version...
    return bytes([
        # Packet length (little-endian, 3 bytes)
        0x4a, 0x00, 0x00,
        # Sequence ID
        0x00,
        # Protocol version (10)
        0x0a,
        # Server version string "5.7.32-0ubuntu0.18.04.1\x00"
        0x35, 0x2e, 0x37, 0x2e, 0x33, 0x32, 0x2d,
        0x30, 0x75, 0x62, 0x75, 0x6e, 0x74, 0x75,
        0x30, 0x2e, 0x31, 0x38, 0x2e, 0x30, 0x34,
        0x2e, 0x31, 0x00,
        # Connection ID (4 bytes)
        0x08, 0x00, 0x00, 0x00,
        # Auth plugin data part 1 (8 bytes)
        0x3a, 0x23, 0x3d, 0x4e, 0x50, 0x56, 0x7a, 0x54,
        # Filler
        0x00,
        # Capability flags lower (2 bytes)
        0xff, 0xf7,
        # Character set
        0x21,
        # Status flags (2 bytes)
        0x02, 0x00,
        # Capability flags upper (2 bytes)
        0xff, 0x81,
        # Auth plugin data length
        0x15,
        # Reserved (10 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        # Auth plugin data part 2 (13 bytes)
        0x6b, 0x34, 0x7e, 0x4d, 0x23, 0x5a, 0x60, 0x65, 0x25, 0x4f, 0x21, 0x2a, 0x00,
        # Auth plugin name
        0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65,
        0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
    ])


@pytest.fixture
def sample_redis_info():
    """Returns a sample Redis INFO response."""
    return b"""$2759
# Server
redis_version:6.2.6
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:1234567890abcdef
redis_mode:standalone
os:Linux 5.4.0-91-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:c11-builtin
gcc_version:9.3.0
process_id:1
process_supervised:no
run_id:abc123def456abc123def456abc123def456abc1
tcp_port:6379
server_time_usec:1640000000000000
uptime_in_seconds:86400
uptime_in_days:1
hz:10
configured_hz:10
lru_clock:12345678
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0

# Clients
connected_clients:1
cluster_connections:0
maxclients:10000
client_recent_max_input_buffer:0
client_recent_max_output_buffer:0
blocked_clients:0
tracking_clients:0
clients_in_timeout_table:0

# Memory
used_memory:1000000
used_memory_human:976.56K
used_memory_rss:2000000
used_memory_rss_human:1.91M
used_memory_peak:1500000
used_memory_peak_human:1.43M
used_memory_peak_perc:66.67%
used_memory_overhead:800000
used_memory_startup:700000
used_memory_dataset:200000
used_memory_dataset_perc:66.67%
allocator_allocated:1000000
allocator_active:1200000
allocator_resident:1800000
total_system_memory:16000000000
total_system_memory_human:14.90G
used_memory_lua:37888
used_memory_lua_human:37.00K
used_memory_scripts:0
used_memory_scripts_human:0B
number_of_cached_scripts:0
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.20
allocator_frag_bytes:200000
allocator_rss_ratio:1.50
allocator_rss_bytes:600000
rss_overhead_ratio:1.11
rss_overhead_bytes:200000
mem_fragmentation_ratio:2.00
mem_fragmentation_bytes:1000000
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_clients_slaves:0
mem_clients_normal:0
mem_aof_buffer:0
mem_allocator:jemalloc-5.2.1
active_defrag_running:0
lazyfree_pending_objects:0
lazyfreed_objects:0

# Replication
role:master
connected_slaves:0
master_failover_state:no-failover
master_replid:abc123def456abc123def456abc123def456abc1
master_replid2:0000000000000000000000000000000000000000
master_repl_offset:0
second_repl_offset:-1
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:10.000000
used_cpu_user:5.000000
used_cpu_sys_children:0.000000
used_cpu_user_children:0.000000
used_cpu_sys_main_thread:10.000000
used_cpu_user_main_thread:5.000000

# Modules

# Errorstats

# Cluster
cluster_enabled:0

# Keyspace
db0:keys=10,expires=0,avg_ttl=0
"""
