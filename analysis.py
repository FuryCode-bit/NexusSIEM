# analysis.py

import pandas as pd
import ipaddress
import logging
from collections import defaultdict, Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False
    logging.warning("geoip2 library not found. Geolocation analysis will be skipped. Install with: pip install geoip2-city")

INTERNAL_NETWORK_CIDR = '192.168.110.0/24'

DNS_PORT = 53
HTTPS_PORT = 443

LATERAL_MOVEMENT_NEW_CONN_THRESHOLD = 5
INTERNAL_COMM_SPIKE_FACTOR = 10
INTERNAL_HTTPS_NEW_CONN_VOLUME_MB = 100
INTERNAL_HTTPS_VOLUME_SPIKE_FACTOR = 20

DNS_TUNNELING_RATIO_THRESHOLD = 5.0
DNS_SHARE_VARIATION_THRESHOLD = 10.0
HTTPS_BEACONING_MIN_FLOWS = 20
HTTPS_BEACONING_MAX_STD_DEV = 1.0
HTTPS_EXFIL_MIN_UPLOAD_BYTES = 500_000_000  # 500 MB
HTTPS_EXFIL_TOP_N_DESTINATIONS = 5

CRITICAL_RISK_GEO = [
    'KP',  # North Korea
    'IR',  # Iran
    'RU',  # Russia
    'SY'   # Syria
]

HIGH_RISK_GEO = [
    'CN',  # China
    'UA',  # Ukraine
]

ANOMALOUS_TIMING_STD_DEV_THRESHOLD = 2.5

APPLICATION_PROTOCOLS = {
    '21': 'FTP',
    '22': 'SSH',
    '23': 'Telnet',
    '25': 'SMTP',
    '53': 'DNS',
    '80': 'HTTP',
    '110': 'POP3',
    '143': 'IMAP',
    '443': 'HTTPS',
    '445': 'SMB',
    '993': 'IMAPS',
    '995': 'POP3S',
    '1433': 'MS SQL',
    '3306': 'MySQL',
    '3389': 'RDP',
    '5900': 'VNC',
    '8080': 'HTTP Proxy'
}

SCORES = {
    "HTTPS_BEACON": 40,
    "DNS_TUNNEL": 40,
    "DNS_BEACON": 40,
    "HTTPS_EXFIL": 45,
    "HTTPS_EXFIL_PER_GB": 10,
    "CRITICAL_RISK_GEO": 40,
    "HIGH_RISK_GEO": 20,
    "NEW_GEO": 10,
    "LATERAL_SCAN": 15,
    "INTERNAL_DNS_TUNNEL": 40,
    "DNS_SHARE_INCREASE": 20,
    "INTERNAL_DNS_SINKHOLE": 30,
    "NEW_HTTPS_VOLUME": 35,
    "VOLUME_SPIKE": 25,
    "CONN_SPIKE": 2,
    "CONN_SPIKE_PER_100X": 8,
    "BRUTE_FORCE": 35,
    "IMPOSSIBLE_TRAVEL": 40,
    "ANOMALOUS_TIMING": 30,
}
CRITICAL_COMBO_MULTIPLIER = 1.5


class UltimateSIEM:
    """
    A comprehensive, unified SIEM library to analyze network traffic,
    detect threats, and generate data for reports and visualizations.
    """
    def __init__(self, baseline_path, anomalous_path, servers_path, geoip_db_path=None):
        """Initializes the SIEM analyzer with data paths and configuration."""
        self.baseline_path = baseline_path
        self.anomalous_path = anomalous_path
        self.servers_path = servers_path
        self.geoip_db_path = geoip_db_path

        self.internal_network = ipaddress.IPv4Network(INTERNAL_NETWORK_CIDR)

        self.suspicion_report = defaultdict(lambda: {'reasons': [], 'score': 0, 'tags': set()})

        self.baseline_df, self.anomalous_df, self.servers_df = None, None, None
        self.geoip_reader = None

        self.new_internal_comms = pd.DataFrame()
        self.all_anomalous_internal_comms = pd.DataFrame()
        self.brute_force_candidates = pd.DataFrame()
        self.https_exfil_candidates = pd.DataFrame()
        self.https_beaconing_candidates = pd.DataFrame()
        self.impossible_travel_candidates = pd.DataFrame()
        self.anomalous_timing_candidates = pd.DataFrame()
        self.suspicious_geo_comms = pd.DataFrame()
        self.baseline_geo_comms = pd.DataFrame()
        self.dns_beaconing_candidates = pd.DataFrame()
        self.dns_tunneling_candidates = pd.DataFrame()
        self.after_hours_suspects = pd.DataFrame()
        self.hourly_suspect_activity = pd.DataFrame()
        self.connection_duration_anomalies = pd.DataFrame()
        self.upload_volume_anomalies = pd.DataFrame()
        self.suspicious_up_down_ratios = pd.DataFrame()
        self.source_networks = pd.DataFrame()

        self.baseline_protocol_counts = None
        self.anomalous_protocol_counts = None
        self.baseline_port_counts = None
        self.anomalous_port_counts = None

        self.baseline_dns_volume = pd.DataFrame()
        self.anomalous_dns_volume = pd.DataFrame()
        self.dns_volume_variation = pd.DataFrame()

        self.internal_correlation_scores = pd.DataFrame()
        self.external_correlation_scores = pd.DataFrame()
        self.confirmed_cnc_channels = []
        self.active_internal_intruders = []
        self.full_internal_compromise = []
        self.active_and_stealthy_bots = []
        self.brute_force_and_stealthy_bots = []

        self.internal_server_traffic = pd.DataFrame()
        self.identified_servers = []
        self.server_profiles = {}
    
        self.baseline_https_volume = pd.DataFrame()
        self.anomalous_https_volume = pd.DataFrame()
        self.https_volume_variation = pd.DataFrame()

    def _load_data(self):
        logging.info("Loading datasets...")
        try:
            self.baseline_df = pd.read_parquet(self.baseline_path)
            self.anomalous_df = pd.read_parquet(self.anomalous_path)
            self.servers_df = pd.read_parquet(self.servers_path)
            for df in [self.baseline_df, self.anomalous_df, self.servers_df]:
                df['timestamp_sec'] = df['timestamp'] / 100.0
            return True
        except FileNotFoundError as e:
            logging.error(f"Error loading data: {e}. Please check file paths.")
            return False

    def _load_geoip_db(self):
        if GEOIP_AVAILABLE and self.geoip_db_path:
            try:
                self.geoip_reader = geoip2.database.Reader(self.geoip_db_path)
                logging.info("GeoIP database loaded successfully.")
            except Exception as e:
                logging.error(f"Failed to load GeoIP DB from {self.geoip_db_path}: {e}")

    def _is_internal(self, ip_str):
        try:
            return ipaddress.ip_address(ip_str) in self.internal_network
        except ValueError:
            return False

    def _get_country(self, ip_str):
        if not self.geoip_reader or self._is_internal(str(ip_str)):
            return None
        try:
            return self.geoip_reader.country(ip_str).country.iso_code
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return "Unknown"
        except Exception:
            return "Error"

    def _add_suspicion(self, ip, reason, score, tag):
        self.suspicion_report[ip]['reasons'].append(reason)
        self.suspicion_report[ip]['score'] += score
        self.suspicion_report[ip]['tags'].add(tag)

    def _format_bytes(self, byte_val):
        """Converts a byte value into a human-readable string (KB, MB, GB)."""
        if byte_val is None:
            return ""
        power = 1024
        n = 0
        power_labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
        while byte_val >= power and n < len(power_labels) -1 :
            byte_val /= power
            n += 1
        return f"{byte_val:.1f} {power_labels[n]}"

    def identify_internal_servers(self):
        """
        Identifies internal hosts that only act as destinations (servers)
        and never initiate internal connections, based on traffic patterns.
        """
        logging.info("Identifying internal-only servers based on traffic directionality.")

        if self.baseline_df is None or self.anomalous_df is None:
            logging.warning("DataFrames not loaded. Skipping internal server identification.")
            return

        full_df = pd.concat([self.baseline_df, self.anomalous_df], ignore_index=True)

        internal_comms = full_df[
            full_df.apply(lambda r: self._is_internal(r['src_ip']) and self._is_internal(r['dst_ip']), axis=1)
        ].copy()

        if internal_comms.empty:
            logging.info("No internal-to-internal communication found.")
            return

        initiators = set(internal_comms['src_ip'].unique())
        receivers = set(internal_comms['dst_ip'].unique())

        server_ips = list(receivers - initiators)
        self.identified_servers = server_ips

        if not server_ips:
            logging.info("No hosts found that exclusively act as servers within the internal network.")
            self.internal_server_traffic = pd.DataFrame()
        else:
            logging.info(f"Identified {len(server_ips)} potential internal-only servers: {server_ips}")
            self.internal_server_traffic = internal_comms[internal_comms['dst_ip'].isin(server_ips)]

    def profile_identified_servers(self, top_n_ports=2):
        """
        Analyzes traffic to identified servers to determine their role based on common ports.
        """
        if not self.identified_servers:
            logging.info("No servers identified to profile.")
            return

        logging.info("Profiling identified internal servers by port usage...")
        self.server_profiles = {}

        for server_ip in self.identified_servers:
            server_traffic = self.internal_server_traffic[
                self.internal_server_traffic['dst_ip'] == server_ip
            ]

            if server_traffic.empty:
                self.server_profiles[server_ip] = "No Inbound Traffic"
                continue

            port_counts = server_traffic['port'].value_counts()
            top_ports = port_counts.nlargest(top_n_ports).index.tolist()

            service_names = [
                APPLICATION_PROTOCOLS.get(str(port), f"Port {port}") for port in top_ports
            ]
            
            profile_string = ", ".join(service_names)
            self.server_profiles[server_ip] = profile_string
            logging.info(f"  - Server {server_ip} profiled as: {profile_string}")

    def profile_network_traffic(self):
        """
        Performs high-level profiling including protocol, port, and DNS/HTTPS volume analysis.
        """
        logging.info("Profiling baseline and anomalous network traffic...")

        if self.baseline_df is None or self.anomalous_df is None:
            logging.warning("DataFrames not loaded. Skipping network profiling.")
            return

        self.baseline_protocol_counts = self.baseline_df['proto'].value_counts()
        self.anomalous_protocol_counts = self.anomalous_df['proto'].value_counts()
        def categorize_port(port):
            if port == HTTPS_PORT: return 'HTTPS'
            elif port == DNS_PORT: return 'DNS'
            else: return 'Other'
        self.baseline_port_counts = self.baseline_df['port'].apply(categorize_port).value_counts()
        self.anomalous_port_counts = self.anomalous_df['port'].apply(categorize_port).value_counts()

        def analyze_dns_volume(dataframe):
            dns_traffic = dataframe[dataframe['port'] == DNS_PORT].copy()
            if dns_traffic.empty:
                return pd.DataFrame()
            dns_summary = dns_traffic.groupby('src_ip').agg(
                total_up_bytes=('up_bytes', 'sum'),
                total_down_bytes=('down_bytes', 'sum')
            ).reset_index()
            return dns_summary

        self.baseline_dns_volume = analyze_dns_volume(self.baseline_df)
        self.anomalous_dns_volume = analyze_dns_volume(self.anomalous_df)

        baseline_dns = self.baseline_df[self.baseline_df['port'] == DNS_PORT]
        anomalous_dns = self.anomalous_df[self.anomalous_df['port'] == DNS_PORT]
        if not baseline_dns.empty and not anomalous_dns.empty:
            total_vol_base = baseline_dns[['up_bytes', 'down_bytes']].sum().sum()
            total_vol_anom = anomalous_dns[['up_bytes', 'down_bytes']].sum().sum()
            if total_vol_base > 0 and total_vol_anom > 0:
                percent_base = (baseline_dns.groupby('src_ip')[['up_bytes', 'down_bytes']].sum() / total_vol_base) * 100
                percent_anom = (anomalous_dns.groupby('src_ip')[['up_bytes', 'down_bytes']].sum() / total_vol_anom) * 100
                
                merged_percents = pd.merge(percent_base, percent_anom, on='src_ip', suffixes=('_base', '_anom'), how='outer').fillna(0)
                merged_percents['up_bytes_variation'] = merged_percents['up_bytes_anom'] - merged_percents['up_bytes_base']
                merged_percents['down_bytes_variation'] = merged_percents['down_bytes_anom'] - merged_percents['down_bytes_base']
                self.dns_volume_variation = merged_percents[['up_bytes_variation', 'down_bytes_variation']].copy()

        def analyze_https_volume(dataframe):
            https_traffic = dataframe[dataframe['port'] == HTTPS_PORT].copy()
            if https_traffic.empty:
                return pd.DataFrame()
            return https_traffic.groupby('src_ip').agg(
                total_up_bytes=('up_bytes', 'sum'),
                total_down_bytes=('down_bytes', 'sum')
            ).reset_index()

        self.baseline_https_volume = analyze_https_volume(self.baseline_df)
        self.anomalous_https_volume = analyze_https_volume(self.anomalous_df)
        
        baseline_https = self.baseline_df[self.baseline_df['port'] == HTTPS_PORT]
        anomalous_https = self.anomalous_df[self.anomalous_df['port'] == HTTPS_PORT]
        if not baseline_https.empty and not anomalous_https.empty:
            total_vol_base_https = baseline_https[['up_bytes', 'down_bytes']].sum().sum()
            total_vol_anom_https = anomalous_https[['up_bytes', 'down_bytes']].sum().sum()
            if total_vol_base_https > 0 and total_vol_anom_https > 0:
                percent_base_https = (baseline_https.groupby('src_ip')[['up_bytes', 'down_bytes']].sum() / total_vol_base_https) * 100
                percent_anom_https = (anomalous_https.groupby('src_ip')[['up_bytes', 'down_bytes']].sum() / total_vol_anom_https) * 100
                
                merged_percents_https = pd.merge(percent_base_https, percent_anom_https, on='src_ip', suffixes=('_base', '_anom'), how='outer').fillna(0)
                merged_percents_https['up_bytes_variation'] = merged_percents_https['up_bytes_anom'] - merged_percents_https['up_bytes_base']
                merged_percents_https['down_bytes_variation'] = merged_percents_https['down_bytes_anom'] - merged_percents_https['down_bytes_base']
                self.https_volume_variation = merged_percents_https[['up_bytes_variation', 'down_bytes_variation']].copy()

    def analyze_internal_threats(self):
        """Analyzes internal traffic for lateral movement, data staging, and connection spikes."""
        logging.info("Analyzing Internal Threats (Behavioral Analysis for HTTPS/DNS)...")
        baseline_internal = self.baseline_df[self.baseline_df.apply(lambda r: self._is_internal(r['src_ip']) and self._is_internal(r['dst_ip']), axis=1)]
        anomalous_internal = self.anomalous_df[self.anomalous_df.apply(lambda r: self._is_internal(r['src_ip']) and self._is_internal(r['dst_ip']), axis=1)]
        if anomalous_internal.empty: return

        aggregation = {'count': ('timestamp_sec', 'size'), 'up_bytes': ('up_bytes', 'sum'), 'down_bytes': ('down_bytes', 'sum')}
        baseline_agg = baseline_internal.groupby(['src_ip', 'dst_ip', 'port']).agg(**aggregation).reset_index()
        anomalous_agg = anomalous_internal.groupby(['src_ip', 'dst_ip', 'port']).agg(**aggregation).reset_index()

        merged_comms = pd.merge(anomalous_agg, baseline_agg, on=['src_ip', 'dst_ip', 'port'], how='left', suffixes=('_anom', '_base')).fillna(0)
        self.all_anomalous_internal_comms = merged_comms.copy()
        self.new_internal_comms = merged_comms[merged_comms['count_base'] == 0].copy()

        if not self.new_internal_comms.empty:
            new_dest_counts = self.new_internal_comms.groupby('src_ip')['dst_ip'].nunique()
            scanners = new_dest_counts[new_dest_counts >= LATERAL_MOVEMENT_NEW_CONN_THRESHOLD]
            for ip, count in scanners.items():
                self._add_suspicion(ip, f"Lateral Movement (Scanning): Initiated new connections to {count} unique internal hosts.", SCORES["LATERAL_SCAN"] * count, "LATERAL_SCAN")

        https_comms = merged_comms[merged_comms['port'] == HTTPS_PORT]
        if not https_comms.empty:
            new_https = https_comms[https_comms['count_base'] == 0]
            high_vol_new_https = new_https[new_https['up_bytes_anom'] >= (INTERNAL_HTTPS_NEW_CONN_VOLUME_MB * 1e6)]
            for _, row in high_vol_new_https.iterrows():
                self._add_suspicion(row['src_ip'], f"Data Staging (HTTPS): A new internal channel to {row['dst_ip']} moved {row['up_bytes_anom']/1e6:.1f} MB.", SCORES["NEW_HTTPS_VOLUME"], "DATA_STAGING")
            existing_https = https_comms[https_comms['count_base'] > 0].copy()
            if not existing_https.empty:
                existing_https['volume_spike_ratio'] = existing_https['up_bytes_anom'] / (existing_https['up_bytes_base'] + 1)
                volume_spikes = existing_https[existing_https['volume_spike_ratio'] >= INTERNAL_HTTPS_VOLUME_SPIKE_FACTOR]
                for _, row in volume_spikes.iterrows():
                    self._add_suspicion(row['src_ip'], f"Data Staging (Volume Spike): Data sent to {row['dst_ip']} spiked {row['volume_spike_ratio']:.0f}x.", SCORES["VOLUME_SPIKE"], "DATA_STAGING")

        merged_comms['count_spike_ratio'] = merged_comms['count_anom'] / (merged_comms['count_base'] + 1)
        spiking_comms = merged_comms[(merged_comms['count_spike_ratio'] >= INTERNAL_COMM_SPIKE_FACTOR) & (merged_comms['count_anom'] >= 20)]
        for _, row in spiking_comms.iterrows():
            spike_factor = row['count_spike_ratio']
            dynamic_score = SCORES["CONN_SPIKE"] + (SCORES["CONN_SPIKE_PER_100X"] * (spike_factor // 100))
            self._add_suspicion(row['src_ip'], f"Anomalous Activity (Spike): Connection count to {row['dst_ip']} on port {row['port']} spiked by {spike_factor:.1f}x.", dynamic_score, "CONN_SPIKE")

    def analyze_dns_variation(self):
        """Analyzes for hosts whose share of DNS traffic has anomalously increased."""
        if self.dns_volume_variation.empty:
            return

        logging.info("Analyzing for anomalous changes in DNS traffic share...")
        up_increase_suspects = self.dns_volume_variation[
            self.dns_volume_variation['up_bytes_variation'] > DNS_SHARE_VARIATION_THRESHOLD
        ]

        for ip, row in up_increase_suspects.iterrows():
            variation = row['up_bytes_variation']
            reason = (f"DNS Traffic Share Increase: Host's share of total DNS upload "
                    f"traffic increased by {variation:.2f} percentage points.")
            self._add_suspicion(ip, reason, SCORES["DNS_SHARE_INCREASE"], "DNS_SHARE_INCREASE")

    def analyze_exfiltration_and_cc(self):
        """Analyzes for exfiltration and C&C channels via DNS and HTTPS."""
        logging.info("Analyzing Exfiltration and C&C (DNS, HTTPS)...")

        dns_traffic = self.anomalous_df[self.anomalous_df['port'] == DNS_PORT].copy()
        if not dns_traffic.empty:
            dns_summary = dns_traffic.groupby('src_ip').agg(up=('up_bytes', 'sum'), down=('down_bytes', 'sum')).reset_index()
            dns_summary['ratio'] = dns_summary['up'] / (dns_summary['down'] + 1)
            tunneling_candidates = dns_summary[dns_summary['ratio'] > DNS_TUNNELING_RATIO_THRESHOLD]
            self.dns_tunneling_candidates = tunneling_candidates.copy()
            for _, row in tunneling_candidates.iterrows():
                self._add_suspicion(row['src_ip'], f"DNS Tunneling: High upload ratio of {row['ratio']:.1f}.", SCORES["DNS_TUNNEL"], "DNS_TUNNEL")

            dns_traffic.sort_values(['src_ip', 'dst_ip', 'timestamp_sec'], inplace=True)
            dns_traffic['interval'] = dns_traffic.groupby(['src_ip', 'dst_ip'])['timestamp_sec'].diff()
            dns_beacon_check = dns_traffic.groupby(['src_ip', 'dst_ip']).agg(interval_std=('interval', 'std'), flow_count=('timestamp_sec', 'count')).reset_index()
            dns_beaconing_candidates = dns_beacon_check[(dns_beacon_check['flow_count'] > 20) & (dns_beacon_check['interval_std'] < 10.0)]
            self.dns_beaconing_candidates = dns_beaconing_candidates.copy()

        https_traffic = self.anomalous_df[self.anomalous_df['port'] == HTTPS_PORT].copy()
        if not https_traffic.empty:
            https_anomalous_uploads = https_traffic.groupby('src_ip')['up_bytes'].sum()
            self.https_exfil_candidates = https_anomalous_uploads[https_anomalous_uploads > HTTPS_EXFIL_MIN_UPLOAD_BYTES].reset_index()
            for _, row in self.https_exfil_candidates.iterrows():
                src_ip, total_bytes_uploaded = row['src_ip'], row['up_bytes']
                gb_uploaded = total_bytes_uploaded / 1e9
                dynamic_score = SCORES["HTTPS_EXFIL"] + (SCORES["HTTPS_EXFIL_PER_GB"] * gb_uploaded)
                source_exfil_traffic = https_traffic[https_traffic['src_ip'] == src_ip]
                top_destinations = source_exfil_traffic.groupby('dst_ip')['up_bytes'].sum().sort_values(ascending=False)
                reason_lines = [f"HTTPS Exfil: Anomalous upload of {self._format_bytes(total_bytes_uploaded)}. Top destinations:"]
                top_n_dest = top_destinations.head(HTTPS_EXFIL_TOP_N_DESTINATIONS)
                for dest_ip, byte_count in top_n_dest.items():
                    country = self._get_country(dest_ip)
                    geo_info = f" [{country}]" if country else ""
                    reason_lines.append(f"      -> {dest_ip}{geo_info} ({self._format_bytes(byte_count)})")
                self._add_suspicion(src_ip, "\n".join(reason_lines), dynamic_score, "HTTPS_EXFIL")

            https_traffic.sort_values(['src_ip', 'dst_ip', 'timestamp_sec'], inplace=True)
            https_traffic['interval'] = https_traffic.groupby(['src_ip', 'dst_ip'])['timestamp_sec'].diff()
            beacon_check = https_traffic.groupby(['src_ip', 'dst_ip']).agg(interval_std=('interval', 'std'), flow_count=('timestamp_sec', 'count')).reset_index()
            self.https_beaconing_candidates = beacon_check[(beacon_check['flow_count'] > HTTPS_BEACONING_MIN_FLOWS) & (beacon_check['interval_std'] < HTTPS_BEACONING_MAX_STD_DEV)]
            for _, row in self.https_beaconing_candidates.iterrows():
                country = self._get_country(row['dst_ip'])
                geo_info = f" [{country}]" if country else ""
                self._add_suspicion(row['src_ip'], f"HTTPS C&C Beacon: Periodic connection to {row['dst_ip']}{geo_info} (std dev: {row['interval_std']:.2f}s).", SCORES["HTTPS_BEACON"], "HTTPS_BEACON")

    def analyze_anomalous_destinations(self):
        """Analyzes external destinations for connections to high-risk or new countries."""
        if not self.geoip_reader: return
        logging.info("Analyzing for Anomalous External Destinations with Tiered Risk...")
        
        baseline_external = self.baseline_df[~self.baseline_df['dst_ip'].apply(self._is_internal)].copy()
        if not baseline_external.empty:
            baseline_external['country'] = baseline_external['dst_ip'].apply(self._get_country)
            self.baseline_geo_comms = baseline_external.copy()
        
        baseline_countries = set(self.baseline_geo_comms['country'].dropna()) if not self.baseline_geo_comms.empty else set()
        
        anomalous_external = self.anomalous_df[~self.anomalous_df['dst_ip'].apply(self._is_internal)].copy()
        if anomalous_external.empty: return
        anomalous_external['country'] = anomalous_external['dst_ip'].apply(self._get_country)
        self.suspicious_geo_comms = anomalous_external.copy()

        geo_summary = anomalous_external.groupby(['src_ip', 'country']).size().reset_index()
        for _, row in geo_summary.iterrows():
            country, ip = row['country'], row['src_ip']
            if not country or country in ["Unknown", "Error"]: continue
            
            if country in CRITICAL_RISK_GEO:
                self._add_suspicion(ip, f"Anomalous Dest: Communicated with CRITICAL-RISK country {country}.", SCORES["CRITICAL_RISK_GEO"], "CRITICAL_RISK_GEO")
            elif country in HIGH_RISK_GEO:
                self._add_suspicion(ip, f"Anomalous Dest: Communicated with high-risk country {country}.", SCORES["HIGH_RISK_GEO"], "HIGH_RISK_GEO")
            if country not in baseline_countries:
                self._add_suspicion(ip, f"Anomalous Dest: Communicated with new country {country}.", SCORES["NEW_GEO"], "NEW_GEO")


    def correlate_internal_threats(self):
        """Correlates internal threat findings to identify high-confidence compromised hosts."""
        logging.info("Correlating internal threat indicators...")

        https_exfiltrators = set(self.https_exfil_candidates['src_ip'])
        https_beacons = set(self.https_beaconing_candidates['src_ip'])
        dns_tunnels = set(self.dns_tunneling_candidates['src_ip'])
        dns_beacons = set(self.dns_beaconing_candidates['src_ip'])
        
        external_comms_suspects = https_exfiltrators.union(https_beacons).union(dns_tunnels).union(dns_beacons)
        lateral_scanners = {ip for ip, details in self.suspicion_report.items() if 'LATERAL_SCAN' in details['tags']}
        geo_violators = {ip for ip, details in self.suspicion_report.items() if 'CRITICAL_RISK_GEO' in details['tags'] or 'NEW_GEO' in details['tags']}
        data_stagers = {ip for ip, details in self.suspicion_report.items() if 'DATA_STAGING' in details['tags']}

        master_suspect_list = (
            list(external_comms_suspects) + 
            list(lateral_scanners) + 
            list(geo_violators) + 
            list(data_stagers)
        )
        
        if not master_suspect_list:
            logging.info("No correlated internal threats found.")
            return

        internal_scores = Counter(master_suspect_list)
        scores_df = pd.DataFrame(internal_scores.items(), columns=['src_ip', 'threat_score']).sort_values('threat_score', ascending=False)
        self.internal_correlation_scores = scores_df

        self.confirmed_cnc_channels = list(external_comms_suspects.intersection(geo_violators))
        self.active_internal_intruders = list(external_comms_suspects.intersection(lateral_scanners))
        self.full_internal_compromise = list(lateral_scanners.intersection(https_exfiltrators))

    def analyze_external_threats(self):
        """Analyzes external server traffic for various threat vectors."""
        if self.servers_df is None or self.servers_df.empty:
            logging.warning("Servers dataframe is empty. Skipping external threat analysis.")
            return
        logging.info("Analyzing external threats on corporate servers (serversX.parquet)...")

        df_servers = self.servers_df.copy()

        df_servers.sort_values(by=['src_ip', 'timestamp_sec'], inplace=True)
        df_servers['interval'] = df_servers.groupby('src_ip')['timestamp_sec'].diff().fillna(0)

        interval_stats = df_servers.groupby('src_ip')['interval'].agg(['std', 'count']).reset_index()
        self.anomalous_timing_candidates = interval_stats[interval_stats['count'] > 50].sort_values('std')
        rhythmic_bots = self.anomalous_timing_candidates[self.anomalous_timing_candidates['std'] < ANOMALOUS_TIMING_STD_DEV_THRESHOLD]
        for _, row in rhythmic_bots.iterrows():
            self._add_suspicion(row['src_ip'], f"Anomalous Timing (Bot): Highly periodic requests (std dev: {row['std']:.2f}s).", SCORES["ANOMALOUS_TIMING"], "ANOMALOUS_TIMING")

        duration_threshold = df_servers['interval'].quantile(0.99)
        self.connection_duration_anomalies = df_servers[df_servers['interval'] > duration_threshold].copy()
        
        df_servers['hour'] = (df_servers['timestamp_sec'] // 3600) % 24
        after_hours_df = df_servers[(df_servers['hour'] < 8) | (df_servers['hour'] >= 20)]
        suspect_totals = after_hours_df['src_ip'].value_counts().reset_index()
        suspect_totals.columns = ['src_ip', 'after_hours_connections']
        self.after_hours_suspects = suspect_totals.head(50).copy()
        if not suspect_totals.empty:
            top_suspect_ips_heatmap = suspect_totals.head(15)['src_ip'].tolist()
            self.hourly_suspect_activity = df_servers[df_servers['src_ip'].isin(top_suspect_ips_heatmap)].pivot_table(
                index='src_ip', columns='hour', values='timestamp', aggfunc='count', fill_value=0
            )

        conn_counts = df_servers.groupby('src_ip').size().reset_index(name='connection_count')
        self.brute_force_candidates = conn_counts.sort_values('connection_count', ascending=False)
        for _, row in self.brute_force_candidates[self.brute_force_candidates['connection_count'] > 1000].iterrows():
            self._add_suspicion(row['src_ip'], f"Connection Flood: High connection count ({row['connection_count']}).", SCORES["BRUTE_FORCE"], "BRUTE_FORCE")

        if self.geoip_reader:
            travel_df = df_servers[['src_ip']].drop_duplicates()
            travel_df['country'] = travel_df['src_ip'].apply(self._get_country)
            travel_df = travel_df[travel_df['country'].notna() & (travel_df['country'] != 'Unknown')]
            country_counts = travel_df.groupby('src_ip')['country'].nunique()
            impossible_travelers = country_counts[country_counts > 1]
            self.impossible_travel_candidates = impossible_travelers.reset_index().rename(columns={'country': 'country_count'})
            for ip, count in impossible_travelers.items():
                self._add_suspicion(ip, f"Impossible Travel: Client connected from {count} different countries.", SCORES["IMPOSSIBLE_TRAVEL"], "IMPOSSIBLE_TRAVEL")

        if len(df_servers) > 1:
            df_servers['up_bytes_zscore'] = df_servers.groupby('src_ip')['up_bytes'].transform(lambda x: (x - x.mean()) / x.std() if x.std() > 0 else 0)
            self.upload_volume_anomalies = df_servers[(df_servers['up_bytes_zscore'] > 3) & (df_servers['up_bytes'] > 1e6)].copy()

        df_servers['network'] = df_servers['src_ip'].apply(lambda ip: str(ipaddress.ip_network(f"{ip}/24", strict=False)))
        network_counts = df_servers.groupby('network')['src_ip'].nunique().reset_index(name='unique_client_ips')
        self.source_networks = network_counts.sort_values('unique_client_ips', ascending=False)
        
        df_servers['up_down_ratio'] = df_servers['up_bytes'] / (df_servers['down_bytes'] + 1)
        avg_ratios = df_servers.groupby('src_ip')['up_down_ratio'].mean().reset_index()
        self.suspicious_up_down_ratios = avg_ratios.sort_values('up_down_ratio', ascending=False)

    def correlate_external_threats(self):
        """Correlates external threat findings to identify the most suspicious clients."""
        logging.info("Correlating external threat indicators...")

        rhythmic_bots = set(self.anomalous_timing_candidates['src_ip']) if not self.anomalous_timing_candidates.empty else set()
        stealthy_bots = set(self.connection_duration_anomalies['src_ip']) if not self.connection_duration_anomalies.empty else set()
        after_hours_suspects = set(self.after_hours_suspects['src_ip']) if not self.after_hours_suspects.empty else set()
        brute_forcers = set(self.brute_force_candidates.head(50)['src_ip']) if not self.brute_force_candidates.empty else set()
        impossible_travelers = set(self.impossible_travel_candidates['src_ip']) if not self.impossible_travel_candidates.empty else set()

        master_suspect_list = list(rhythmic_bots) + list(stealthy_bots) + list(after_hours_suspects) + list(brute_forcers) + list(impossible_travelers)
        if not master_suspect_list:
            logging.info("No correlated external threats found.")
            return
            
        overall_scores = Counter(master_suspect_list)
        scores_df = pd.DataFrame(overall_scores.items(), columns=['src_ip', 'detection_score']).sort_values('detection_score', ascending=False)
        self.external_correlation_scores = scores_df

        self.active_and_stealthy_bots = list(after_hours_suspects.intersection(stealthy_bots))
        self.brute_force_and_stealthy_bots = list(brute_forcers.intersection(stealthy_bots))

    def run_full_analysis(self):
        """Executes the complete analysis pipeline from data loading to correlation."""
        if not self._load_data(): return
        self._load_geoip_db()
        self.identify_internal_servers()
        self.profile_identified_servers()
        self.profile_network_traffic()
        self.analyze_internal_threats()
        self.analyze_exfiltration_and_cc()
        self.analyze_dns_variation()
        self.analyze_anomalous_destinations()
        self.analyze_external_threats()
        self.correlate_internal_threats()
        self.correlate_external_threats()

    def generate_final_report(self):
        """Generates a multi-part text report for internal and external threats."""
        print("\n" + "="*80 + "\n" + "🚨 SIEM REPORT: POTENTIALLY ANOMALOUS INTERNAL DEVICES 🚨".center(80) + "\n" + "="*80)
        internal_report = {ip: d for ip, d in self.suspicion_report.items() if self._is_internal(ip)}
        if not internal_report:
            print("\n✅ No suspicious internal devices detected.".center(80))
        else:
            final_scores = {}
            for ip, details in internal_report.items():
                score = details['score']
                if ("LATERAL_SCAN" in details['tags'] and "HTTPS_EXFIL" in details['tags']) or \
                   ("HTTPS_BEACON" in details['tags'] and "HTTPS_EXFIL" in details['tags']):
                    score *= CRITICAL_COMBO_MULTIPLIER
                    details['reasons'].append(f"CRITICAL COMBO: Score multiplied by {CRITICAL_COMBO_MULTIPLIER}x.")
                final_scores[ip] = {'score': int(score), 'reasons': details['reasons']}
            
            sorted_hosts = sorted(final_scores.items(), key=lambda item: item[1]['score'], reverse=True)
            print(f"\nFound {len(sorted_hosts)} potentially anomalous internal device(s):\n")
            for ip, details in sorted_hosts:
                print(f"--- DEVICE: {ip} | Suspicion Score: {details['score']} ---")
                for reason in sorted(details['reasons'], key=lambda r: "CRITICAL" in r, reverse=True): print(f"  - {reason}")
                print("-" * (len(ip) + 33))

        print("\n" + "="*80 + "\n" + "🚨 SIEM REPORT: SUSPICIOUS EXTERNAL CLIENTS (CANDIDATES FOR BLOCKING) 🚨".center(80) + "\n" + "="*80)
        external_report = {ip: d for ip, d in self.suspicion_report.items() if not self._is_internal(ip)}
        if not external_report:
            print("\n✅ No suspicious external clients detected.".center(80))
        else:
            sorted_hosts = sorted(external_report.items(), key=lambda item: item[1]['score'], reverse=True)
            print(f"\nFound {len(sorted_hosts)} external client(s) with anomalous behavior:\n")
            for ip, details in sorted_hosts:
                print(f"--- EXTERNAL CLIENT: {ip} | Suspicion Score: {details['score']} ---")
                for reason in details['reasons']: print(f"  - {reason}")
                print("-" * (len(ip) + 38))
        print("\n" + "="*80)