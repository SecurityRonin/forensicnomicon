/// Well-known suspicious/attacker-favoured TCP/UDP ports.
///
/// Sources:
/// - SANS Internet Storm Center — port threat data:
///   <https://isc.sans.edu/port.html>
/// - Cobalt Strike port 50050 — documented in Raphael Mudge's own blog post,
///   "Cobalt Strike Team Server Population Study" (Feb 2019):
///   <https://www.cobaltstrike.com/blog/cobalt-strike-team-server-population-study>
///   Also documented in the official HelpSystems user guide:
///   <https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/welcome_starting-cs-client.htm>
/// - Recorded Future — Insikt Group, "A Multi-Method Approach to Identifying
///   Rogue Cobalt Strike Servers" (Jun 2019), uses port 50050 as a detection signal:
///   <https://www.recordedfuture.com/research/cobalt-strike-servers>
/// - Tor Project — relay (9001) and directory (9030) port assignments:
///   <https://support.torproject.org/tbb/tbb-firewall-ports/>
/// - Microsoft — WinRM port assignments (5985 HTTP, 5986 HTTPS, 47001 alt):
///   <https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management>
pub const SUSPICIOUS_PORTS: &[u16] = &[
    4444,  // Metasploit default
    50050, // Cobalt Strike teamserver
    31337, // eleet / Back Orifice
    1337,  // leet
    8888,  // common C2 / jupyter abuse
    9999,  // common C2
    4445,  // Metasploit variant
    1234,  // common test/C2 port
    6666,  // IRC / C2
    7777,  // common C2
    8080,  // HTTP proxy / C2 (beyond the HTTP norm)
    9001,  // Tor relay (ORPort)
    9030,  // Tor directory (DirPort)
    4899,  // Radmin
    5900,  // VNC
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    47001, // WinRM alt
];

/// Returns `true` if `port` appears in [`SUSPICIOUS_PORTS`].
pub fn is_suspicious_port(port: u16) -> bool {
    SUSPICIOUS_PORTS.contains(&port)
}

/// Ports specifically associated with C2 frameworks (Cobalt Strike, Metasploit,
/// Empire, Havoc, Sliver, Brute Ratel).
pub const C2_FRAMEWORK_PORTS: &[u16] = &[
    4444,  // Metasploit default listener
    4445,  // Metasploit variant
    50050, // Cobalt Strike teamserver
    31337, // Back Orifice / eleet
    8443,  // Empire / CS HTTPS C2
    60000, // Havoc C2 default
    5001,  // Sliver mTLS default
    5002,  // Sliver WireGuard default
    8888,  // Brute Ratel C4 / common
    7777,  // common C2
    9999,  // common C2
    2222,  // Sliver HTTP(S) variant
];

/// Ports used for outbound database connections — lateral movement indicator when
/// seen on non-database hosts.
pub const DATABASE_PORTS: &[u16] = &[
    1433,  // Microsoft SQL Server
    1434,  // MSSQL Browser
    3306,  // MySQL / MariaDB
    5432,  // PostgreSQL
    27017, // MongoDB
    27018, // MongoDB shard
    6379,  // Redis
    6380,  // Redis TLS
    1521,  // Oracle DB
    1830,  // Oracle TNS variant
    5984,  // CouchDB
    8086,  // InfluxDB
    9200,  // Elasticsearch HTTP
    9300,  // Elasticsearch transport
];

/// Returns `true` if `port` is a known C2 framework port.
pub fn is_c2_port(port: u16) -> bool {
    C2_FRAMEWORK_PORTS.contains(&port)
}

/// Returns `true` if `port` is a well-known database server port.
///
/// Seeing this on a non-database host is a lateral-movement indicator.
pub fn is_database_port(port: u16) -> bool {
    DATABASE_PORTS.contains(&port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_metasploit_default_4444() {
        assert!(
            is_suspicious_port(4444),
            "4444 (Metasploit default) should be suspicious"
        );
    }

    #[test]
    fn detects_cobalt_strike_50050() {
        assert!(
            is_suspicious_port(50050),
            "50050 (Cobalt Strike teamserver) should be suspicious"
        );
    }

    #[test]
    fn detects_eleet_31337() {
        assert!(
            is_suspicious_port(31337),
            "31337 (eleet) should be suspicious"
        );
    }

    #[test]
    fn detects_tor_9001() {
        assert!(
            is_suspicious_port(9001),
            "9001 (Tor relay) should be suspicious"
        );
    }

    #[test]
    fn detects_winrm_5985() {
        assert!(
            is_suspicious_port(5985),
            "5985 (WinRM) should be suspicious"
        );
    }

    #[test]
    fn allows_port_80() {
        assert!(
            !is_suspicious_port(80),
            "port 80 (HTTP) should not be suspicious"
        );
    }

    #[test]
    fn allows_port_443() {
        assert!(
            !is_suspicious_port(443),
            "port 443 (HTTPS) should not be suspicious"
        );
    }

    #[test]
    fn port_zero_not_suspicious() {
        assert!(!is_suspicious_port(0), "port 0 should not be flagged");
    }

    #[test]
    fn port_65535_not_suspicious() {
        assert!(
            !is_suspicious_port(65535),
            "port 65535 (max) should not be flagged by default"
        );
    }

    #[test]
    fn suspicious_ports_contains_4444() {
        assert!(SUSPICIOUS_PORTS.contains(&4444));
    }

    #[test]
    fn suspicious_ports_contains_9030() {
        assert!(SUSPICIOUS_PORTS.contains(&9030), "9030 (Tor dir) missing");
    }

    #[test]
    fn suspicious_ports_contains_radmin_4899() {
        assert!(SUSPICIOUS_PORTS.contains(&4899), "4899 (Radmin) missing");
    }

    // --- C2_FRAMEWORK_PORTS / is_c2_port ---
    #[test]
    fn c2_ports_contains_4444() {
        assert!(C2_FRAMEWORK_PORTS.contains(&4444));
    }
    #[test]
    fn c2_ports_contains_50050() {
        assert!(C2_FRAMEWORK_PORTS.contains(&50050));
    }
    #[test]
    fn c2_ports_contains_8443() {
        assert!(C2_FRAMEWORK_PORTS.contains(&8443));
    }
    #[test]
    fn detects_metasploit_c2_port() {
        assert!(is_c2_port(4444));
    }
    #[test]
    fn detects_cobalt_strike_c2_port() {
        assert!(is_c2_port(50050));
    }
    #[test]
    fn detects_havoc_c2_port() {
        assert!(is_c2_port(60000));
    }
    #[test]
    fn port_80_not_c2() {
        assert!(!is_c2_port(80));
    }
    #[test]
    fn port_443_not_c2() {
        assert!(!is_c2_port(443));
    }
    #[test]
    fn port_22_not_c2() {
        assert!(!is_c2_port(22));
    }

    // --- DATABASE_PORTS / is_database_port ---
    #[test]
    fn database_ports_contains_mssql() {
        assert!(DATABASE_PORTS.contains(&1433));
    }
    #[test]
    fn database_ports_contains_mysql() {
        assert!(DATABASE_PORTS.contains(&3306));
    }
    #[test]
    fn database_ports_contains_postgres() {
        assert!(DATABASE_PORTS.contains(&5432));
    }
    #[test]
    fn detects_mssql_port() {
        assert!(is_database_port(1433));
    }
    #[test]
    fn detects_redis_port() {
        assert!(is_database_port(6379));
    }
    #[test]
    fn detects_mongodb_port() {
        assert!(is_database_port(27017));
    }
    #[test]
    fn port_80_not_database() {
        assert!(!is_database_port(80));
    }
    #[test]
    fn port_4444_not_database() {
        assert!(!is_database_port(4444));
    }
}
