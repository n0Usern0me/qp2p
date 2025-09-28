
import time

import threading

from collections import defaultdict, deque

from typing import Dict, Tuple, Set



class DDoSProtection:

    """Enhanced DDoS attack protection with site verification awareness - English interface"""

    

    def __init__(self, max_requests_per_minute: int = 60, max_requests_per_second: int = 10, 

                 blacklist_threshold: int = 100, blacklist_duration: int = 3600,

                 signature_failure_threshold: int = 50):

        self.max_requests_per_minute = max_requests_per_minute

        self.max_requests_per_second = max_requests_per_second

        self.blacklist_threshold = blacklist_threshold

        self.blacklist_duration = blacklist_duration

        self.signature_failure_threshold = signature_failure_threshold

        

        # Track requests per IP

        self.requests_per_minute: Dict[str, deque] = defaultdict(lambda: deque())

        self.requests_per_second: Dict[str, deque] = defaultdict(lambda: deque())

        self.violation_count: Dict[str, int] = defaultdict(int)

        self.blacklisted_ips: Dict[str, float] = {}  # IP -> blacklist_end_time

        

        # Track signature verification failures (potential attack indicator)

        self.signature_failures: Dict[str, deque] = defaultdict(lambda: deque())

        self.malformed_content_count: Dict[str, int] = defaultdict(int)

        

        # Track site-specific activity

        self.site_activity: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

        self.suspicious_sites: Set[str] = set()

        

        self.lock = threading.RLock()

        

        # Start cleanup thread

        self.cleanup_thread = threading.Thread(target=self._cleanup_old_data, daemon=True)

        self.cleanup_thread.start()

        

        print("[DDOS] Enhanced DDoS protection initialized with site verification awareness")

        print(f"[DDOS] Rate limits: {max_requests_per_second}/sec, {max_requests_per_minute}/min")

        print(f"[DDOS] Site signature failure threshold: {signature_failure_threshold}")



    def is_allowed(self, client_ip: str, request_type: str = "general") -> bool:

        """Check if request from client IP is allowed with request type awareness"""

        current_time = time.time()

        

        with self.lock:

            # Check if IP is blacklisted

            if client_ip in self.blacklisted_ips:

                if current_time < self.blacklisted_ips[client_ip]:

                    return False  # Still blacklisted

                else:

                    # Blacklist expired, remove from list

                    del self.blacklisted_ips[client_ip]

                    self.violation_count[client_ip] = 0

                    self.signature_failures[client_ip].clear()

                    self.malformed_content_count[client_ip] = 0

                    print(f"[DDOS] IP {client_ip} blacklist expired, access restored")

            

            # Clean old requests

            self._clean_old_requests(client_ip, current_time)

            

            # Check per-second limit

            if len(self.requests_per_second[client_ip]) >= self.max_requests_per_second:

                self._handle_violation(client_ip, current_time, f"per-second limit exceeded ({request_type})")

                return False

            

            # Check per-minute limit

            if len(self.requests_per_minute[client_ip]) >= self.max_requests_per_minute:

                self._handle_violation(client_ip, current_time, f"per-minute limit exceeded ({request_type})")

                return False

            

            # Record the request

            self.requests_per_second[client_ip].append(current_time)

            self.requests_per_minute[client_ip].append(current_time)

            

            return True



    def report_signature_failure(self, client_ip: str, site_name: str, reason: str = "invalid_signature"):

        """Report a signature verification failure from a specific IP"""

        current_time = time.time()

        

        with self.lock:

            # Track signature failures per IP

            self.signature_failures[client_ip].append(current_time)

            

            # Clean old signature failures (last 10 minutes)

            while (self.signature_failures[client_ip] and 

                   current_time - self.signature_failures[client_ip][0] > 600):

                self.signature_failures[client_ip].popleft()

            

            # Track site-specific suspicious activity

            self.site_activity[client_ip][site_name] += 1

            

            failure_count = len(self.signature_failures[client_ip])

            

            print(f"[DDOS] Signature failure from {client_ip} for site '{site_name}': {reason}")

            print(f"[DDOS] Total signature failures from {client_ip} in last 10min: {failure_count}")

            

            # Check if IP should be flagged for excessive signature failures

            if failure_count >= self.signature_failure_threshold:

                self._handle_signature_attack(client_ip, current_time, failure_count)

            

            # Check for site-specific attack patterns

            site_failures = self.site_activity[client_ip][site_name]

            if site_failures >= 20:  # Threshold for site-specific attacks

                print(f"[DDOS] High failure rate for site '{site_name}' from {client_ip}: {site_failures} failures")

                self.suspicious_sites.add(site_name)



    def report_malformed_content(self, client_ip: str, content_type: str = "unknown"):

        """Report malformed content from a specific IP"""

        with self.lock:

            self.malformed_content_count[client_ip] += 1

            malformed_count = self.malformed_content_count[client_ip]

            

            print(f"[DDOS] Malformed content from {client_ip}: {content_type} (total: {malformed_count})")

            

            # Escalate if too much malformed content

            if malformed_count >= 30:

                current_time = time.time()

                self._handle_violation(client_ip, current_time, f"excessive malformed content ({content_type})")



    def _handle_signature_attack(self, client_ip: str, current_time: float, failure_count: int):

        """Handle potential signature-based attack"""

        print(f"[DDOS] SIGNATURE ATTACK detected from {client_ip}: {failure_count} failures")

        

        # Immediately blacklist IPs with excessive signature failures

        self.blacklisted_ips[client_ip] = current_time + (self.blacklist_duration * 2)  # Double duration

        self.violation_count[client_ip] = self.blacklist_threshold  # Mark as high-risk

        

        self._log_security_event(client_ip, "SIGNATURE_ATTACK", 

                                f"Excessive signature failures: {failure_count}")



    def _clean_old_requests(self, client_ip: str, current_time: float):

        """Remove old request timestamps"""

        # Clean per-second requests (older than 1 second)

        while (self.requests_per_second[client_ip] and 

               current_time - self.requests_per_second[client_ip][0] > 1):

            self.requests_per_second[client_ip].popleft()

        

        # Clean per-minute requests (older than 60 seconds)

        while (self.requests_per_minute[client_ip] and 

               current_time - self.requests_per_minute[client_ip][0] > 60):

            self.requests_per_minute[client_ip].popleft()



    def _handle_violation(self, client_ip: str, current_time: float, reason: str):

        """Handle rate limit violation"""

        self.violation_count[client_ip] += 1

        

        print(f"[DDOS] Rate limit violation from {client_ip}: {reason} (violation count: {self.violation_count[client_ip]})")

        

        # Blacklist IP if too many violations

        if self.violation_count[client_ip] >= self.blacklist_threshold:

            self.blacklisted_ips[client_ip] = current_time + self.blacklist_duration

            print(f"[DDOS] IP {client_ip} blacklisted for {self.blacklist_duration} seconds due to repeated violations")

            

            # Log security event

            self._log_security_event(client_ip, "BLACKLISTED", f"Threshold exceeded: {self.violation_count[client_ip]} violations")



    def _log_security_event(self, client_ip: str, event_type: str, details: str):

        """Log security events for monitoring"""

        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        print(f"[SECURITY] {timestamp} | {event_type} | IP: {client_ip} | Details: {details}")



    def _cleanup_old_data(self):

        """Background thread to clean up old data periodically"""

        while True:

            try:

                time.sleep(300)  # Run every 5 minutes

                current_time = time.time()

                

                with self.lock:

                    # Clean up old blacklist entries

                    expired_ips = [ip for ip, end_time in self.blacklisted_ips.items() 

                                 if current_time >= end_time]

                    for ip in expired_ips:

                        del self.blacklisted_ips[ip]

                        self.violation_count[ip] = 0

                        self.signature_failures[ip].clear()

                        self.malformed_content_count[ip] = 0

                        print(f"[DDOS] Cleaned up expired blacklist entry for {ip}")

                    

                    # Clean old signature failures

                    for ip in list(self.signature_failures.keys()):

                        while (self.signature_failures[ip] and 

                               current_time - self.signature_failures[ip][0] > 600):

                            self.signature_failures[ip].popleft()

                        

                        if not self.signature_failures[ip]:

                            del self.signature_failures[ip]

                    

                    # Clean up empty request deques

                    empty_ips = []

                    for ip in list(self.requests_per_minute.keys()):

                        self._clean_old_requests(ip, current_time)

                        if (not self.requests_per_minute[ip] and 

                            not self.requests_per_second[ip] and

                            ip not in self.blacklisted_ips and

                            self.violation_count[ip] == 0 and

                            ip not in self.signature_failures):

                            empty_ips.append(ip)

                    

                    for ip in empty_ips:

                        del self.requests_per_minute[ip]

                        del self.requests_per_second[ip]

                        del self.violation_count[ip]

                        if ip in self.site_activity:

                            del self.site_activity[ip]

                        

                    # Clean suspicious sites that haven't had recent activity

                    old_suspicious = list(self.suspicious_sites)

                    for site in old_suspicious:

                        site_recent_activity = sum(

                            activity.get(site, 0) for activity in self.site_activity.values()

                        )

                        if site_recent_activity < 5:  # Low recent activity

                            self.suspicious_sites.discard(site)

                        

                    if expired_ips or empty_ips:

                        print(f"[DDOS] Cleanup completed: {len(expired_ips)} expired blacklist, {len(empty_ips)} empty IP records")

                        

            except Exception as e:

                print(f"[DDOS] Cleanup error: {e}")



    def get_stats(self) -> Dict[str, any]:

        """Get current protection statistics with site verification info"""

        with self.lock:

            current_time = time.time()

            active_connections = 0

            total_signature_failures = 0

            

            # Count active connections (requests in last minute)

            for ip, requests in self.requests_per_minute.items():

                if requests and (current_time - requests[-1]) < 60:

                    active_connections += 1

            

            # Count total signature failures

            for failures in self.signature_failures.values():

                total_signature_failures += len(failures)

            

            return {

                "active_ips": len(self.requests_per_minute),

                "active_connections": active_connections,

                "blacklisted_ips": len(self.blacklisted_ips),

                "total_violations": sum(self.violation_count.values()),

                "signature_failures_tracked": len(self.signature_failures),

                "total_signature_failures": total_signature_failures,

                "malformed_content_reports": sum(self.malformed_content_count.values()),

                "suspicious_sites": len(self.suspicious_sites),

                "config": {

                    "max_requests_per_minute": self.max_requests_per_minute,

                    "max_requests_per_second": self.max_requests_per_second,

                    "blacklist_threshold": self.blacklist_threshold,

                    "blacklist_duration": self.blacklist_duration,

                    "signature_failure_threshold": self.signature_failure_threshold

                },

                "security_status": "Active - Site verification aware",

                "protection_level": "Enhanced - Anti-signature attack"

            }



    def get_signature_attack_stats(self) -> Dict[str, any]:

        """Get statistics about signature-based attacks"""

        with self.lock:

            current_time = time.time()

            recent_attacks = []

            

            for ip, failures in self.signature_failures.items():

                if failures and len(failures) >= 10:  # Significant failure count

                    recent_failures = [f for f in failures if current_time - f < 600]  # Last 10 minutes

                    if recent_failures:

                        recent_attacks.append({

                            "ip": ip,

                            "failures_last_10min": len(recent_failures),

                            "total_failures": len(failures),

                            "is_blacklisted": ip in self.blacklisted_ips

                        })

            

            return {

                "recent_signature_attacks": recent_attacks,

                "suspicious_sites": list(self.suspicious_sites),

                "total_ips_with_failures": len(self.signature_failures),

                "attack_threshold": self.signature_failure_threshold,

                "monitoring_window": "10 minutes"

            }



    def get_site_activity_report(self) -> Dict[str, Dict]:

        """Get report of site-specific suspicious activity"""

        with self.lock:

            report = {}

            

            for ip, sites in self.site_activity.items():

                if any(count > 5 for count in sites.values()):  # Only IPs with significant activity

                    report[ip] = {

                        "site_failures": dict(sites),

                        "total_failures": sum(sites.values()),

                        "is_blacklisted": ip in self.blacklisted_ips,

                        "signature_failures": len(self.signature_failures.get(ip, [])),

                        "most_targeted_site": max(sites.items(), key=lambda x: x[1])[0] if sites else None

                    }

            

            return report



    def whitelist_ip(self, client_ip: str):

        """Remove IP from blacklist and clear all violation records"""

        with self.lock:

            cleared_items = []

            

            if client_ip in self.blacklisted_ips:

                del self.blacklisted_ips[client_ip]

                cleared_items.append("blacklist")

            

            if self.violation_count[client_ip] > 0:

                self.violation_count[client_ip] = 0

                cleared_items.append("violations")

            

            if client_ip in self.signature_failures:

                self.signature_failures[client_ip].clear()

                cleared_items.append("signature failures")

            

            if self.malformed_content_count[client_ip] > 0:

                self.malformed_content_count[client_ip] = 0

                cleared_items.append("malformed content")

            

            if client_ip in self.site_activity:

                del self.site_activity[client_ip]

                cleared_items.append("site activity")

            

            print(f"[DDOS] IP {client_ip} whitelisted, cleared: {', '.join(cleared_items)}")

            self._log_security_event(client_ip, "WHITELISTED", f"Cleared: {', '.join(cleared_items)}")



    def report_valid_signature(self, client_ip: str, site_name: str):

        """Report a successful signature verification (can help with reputation)"""

        # This could be used for positive reputation scoring in the future

        pass



    def get_ip_security_profile(self, client_ip: str) -> Dict[str, any]:

        """Get comprehensive security profile for an IP"""

        with self.lock:

            current_time = time.time()

            self._clean_old_requests(client_ip, current_time)

            

            is_blacklisted = self.is_ip_blacklisted(client_ip)

            remaining_blacklist_time = 0

            

            if is_blacklisted:

                remaining_blacklist_time = max(0, self.blacklisted_ips[client_ip] - current_time)

            

            signature_failures = len(self.signature_failures.get(client_ip, []))

            site_targets = dict(self.site_activity.get(client_ip, {}))

            

            # Determine threat level

            threat_level = "LOW"

            if is_blacklisted:

                threat_level = "BLACKLISTED"

            elif signature_failures > 30:

                threat_level = "HIGH"

            elif signature_failures > 10 or sum(site_targets.values()) > 15:

                threat_level = "MEDIUM"

            

            return {

                "ip_address": client_ip,

                "requests_last_second": len(self.requests_per_second[client_ip]),

                "requests_last_minute": len(self.requests_per_minute[client_ip]),

                "violation_count": self.violation_count[client_ip],

                "signature_failures": signature_failures,

                "malformed_content_count": self.malformed_content_count[client_ip],

                "targeted_sites": site_targets,

                "is_blacklisted": is_blacklisted,

                "blacklist_remaining_seconds": int(remaining_blacklist_time),

                "threat_level": threat_level,

                "status": "Blacklisted" if is_blacklisted else threat_level

            }



    def is_ip_blacklisted(self, client_ip: str) -> bool:

        """Check if an IP is currently blacklisted"""

        with self.lock:

            if client_ip in self.blacklisted_ips:

                current_time = time.time()

                if current_time < self.blacklisted_ips[client_ip]:

                    return True

                else:

                    # Clean up expired entry

                    del self.blacklisted_ips[client_ip]

                    self.violation_count[client_ip] = 0

                    self.signature_failures[client_ip].clear()

                    self.malformed_content_count[client_ip] = 0

            return False



    def update_signature_threshold(self, new_threshold: int):

        """Update the signature failure threshold"""

        with self.lock:

            old_threshold = self.signature_failure_threshold

            self.signature_failure_threshold = new_threshold

            print(f"[DDOS] Updated signature failure threshold from {old_threshold} to {new_threshold}")



    def shutdown(self):

        """Shutdown DDoS protection gracefully"""

        print("[DDOS] Shutting down enhanced DDoS protection system...")

        

        with self.lock:

            stats = self.get_stats()

            signature_stats = self.get_signature_attack_stats()

            

            print(f"[DDOS] Final stats: {stats['active_ips']} active IPs, {stats['blacklisted_ips']} blacklisted")

            print(f"[DDOS] Signature attacks detected: {len(signature_stats['recent_signature_attacks'])}")

            print(f"[DDOS] Suspicious sites monitored: {len(signature_stats['suspicious_sites'])}")

        

        print("[DDOS] Enhanced DDoS protection shutdown complete")