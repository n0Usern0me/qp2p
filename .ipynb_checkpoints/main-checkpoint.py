#!/usr/bin/env python3

import os

import sys

import threading

import time

import signal

import platform

import json



sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))



from p2pqs.p2p.node import P2PNode

from p2pqs.core.config import ConfigManager



VERSION = "2.1"

shutdown_event = threading.Event()

node_instance = None



def signal_handler(signum, frame):

    """Handle shutdown signals"""

    global node_instance

    print(f"\n[SHUTDOWN] Signal {signum} received, shutting down...")

    shutdown_event.set()

    if node_instance:

        node_instance.shutdown()

    sys.exit(0)



def setup_signal_handlers():

    """Setup signal handlers"""

    if hasattr(signal, 'SIGTERM'):

        signal.signal(signal.SIGTERM, signal_handler)

    if hasattr(signal, 'SIGINT'):

        signal.signal(signal.SIGINT, signal_handler)



def print_startup_info():

    """Print startup information"""

    print("=" * 70)

    print("  P2P Quantum-Safe Network - Enhanced Edition")

    print(f"  Version {VERSION} - Improved Connection Management")

    print("=" * 70)

    print()



def print_help():

    """Print all available commands"""

    print("\n" + "=" * 70)

    print("AVAILABLE COMMANDS")

    print("=" * 70)

    

    print("\n--- SYSTEM STATUS ---")

    print("  status              Show node status and statistics")

    print("  version             Show version information")

    print("  platform            Show platform compatibility info")

    print("  config              Show current configuration")

    print("  db-path             Show database location")

    

    print("\n--- NETWORK MANAGEMENT ---")

    print("  connect <host>      Connect to peer (default port 4000)")

    print("  connect <host:port> Connect to peer on specific port")

    print("  peers               List all connected peers")

    print("  peer-status         Show detailed peer connection status")

    print("  network-info        Show network statistics and health")

    print("  known-peers         Show all known peers in storage")

    print("  debug-peers         Debug peer connections")

    

    print("\n--- SITE MANAGEMENT ---")

    print("  sites               List all registered sites")

    print("  create <site>       Create a new site")

    print("  keys <site>         Show cryptographic keys for site")

    print("  sync <site>         Sync site with all connected peers")

    

    print("\n--- CONTENT MANAGEMENT ---")

    print("  content [site]      List content (optionally filter by site)")

    print("  content-log         Show content validation log")

    print("  content-valid       Show only valid content received")

    print("  content-invalid     Show only invalid content rejected")

    print("  post <site> <msg>   Post content to site")

    print("  broadcast <site> <msg> Broadcast content to all peers")

    print("  test-broadcast      Test content broadcasting")

    

    print("\n--- API SERVER ---")

    print("  api                 Show API server information")

    

    print("\n--- UTILITIES ---")

    print("  help                Show this help message")

    print("  exit                Shutdown node gracefully")

    print("=" * 70 + "\n")



def format_timestamp(timestamp):

    """Format timestamp for display"""

    try:

        if isinstance(timestamp, str):

            return timestamp

        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

    except:

        return str(timestamp)



def main():

    """Main application entry point"""

    global node_instance

    

    print_startup_info()

    setup_signal_handlers()

    

    print("[INIT] Starting node initialization...")

    

    try:

        config_manager = ConfigManager()

        

        user_id = config_manager.config.get("user_id")

        if not user_id:

            import secrets

            user_id = secrets.token_hex(16)

            config_manager.config["user_id"] = user_id

            config_manager.save()

            print(f"[INIT] Generated new user ID: {user_id}")

        else:

            print(f"[INIT] Using existing user ID: {user_id}")



        api_settings = config_manager.get_api_settings()

        p2p_settings = config_manager.get_p2p_settings()

        

        p2p_port = p2p_settings.get("p2p_port", 4000)

        api_port = 5001

        enable_http = api_settings.get("enable_http", True)



        print(f"[INIT] P2P Port: {p2p_port}")

        print(f"[INIT] API Port: {api_port}")

        print(f"[INIT] HTTP API: {'Enabled' if enable_http else 'Disabled'}")



        node_instance = P2PNode(user_id, p2p_port, enable_http, api_port)

        

        if enable_http:

            print(f"[INIT] HTTP API server started on http://127.0.0.1:{api_port}")



        print(f"[INIT] P2P server listening on port {p2p_port}")

        print(f"[INIT] Node initialized successfully")

        

        platform_info = config_manager.get_platform_info()

        print(f"[INIT] Platform: {platform_info['current_platform']}")

        

        print_help()



        # Main command loop

        while not shutdown_event.is_set():

            try:

                command = input("> ").strip()

                if not command:

                    continue

                    

                cmd_parts = command.split()

                cmd = cmd_parts[0].lower()



                # EXIT COMMANDS

                if cmd in ["exit", "quit", "stop"]:

                    print("[SHUTDOWN] Stopping node...")

                    break



                # HELP COMMAND

                elif cmd in ["help", "h", "?"]:

                    print_help()



                # STATUS COMMAND

                elif cmd == "status":

                    sites = node_instance.database.get_sites()

                    contents = node_instance.database.get_content(limit=10000)

                    peers = node_instance.get_peer_count()

                    content_log = node_instance.get_content_validation_log()

                    valid_content = [c for c in content_log if c['is_valid']]

                    invalid_content = [c for c in content_log if not c['is_valid']]

                    

                    print(f"\n[STATUS] Version: {VERSION}")

                    print(f"[STATUS] Platform: {platform.system()} {platform.release()}")

                    print(f"[STATUS] User ID: {node_instance.crypto.crypto_id}")

                    print(f"[STATUS] Registered sites: {len(sites)}")

                    print(f"[STATUS] Stored content: {len(contents)}")

                    print(f"[STATUS] Connected peers: {peers}/{node_instance.max_peers}")

                    print(f"[STATUS] Known peers: {len(node_instance.known_peers)}")

                    print(f"[STATUS] Content received: {len(content_log)}")

                    print(f"[STATUS] Valid content: {len(valid_content)}")

                    print(f"[STATUS] Invalid content: {len(invalid_content)}")

                    print(f"[STATUS] P2P Port: {node_instance.p2p_port}")

                    print(f"[STATUS] API Port: {node_instance.api_port}")

                    print(f"[STATUS] HTTP API: {'Active' if node_instance.enable_http else 'Disabled'}")

                    print(f"[STATUS] Database: {node_instance.database.db_path}\n")



                # VERSION COMMAND

                elif cmd == "version":

                    print(f"\n[VERSION] P2P Quantum-Safe Network v{VERSION}")

                    print(f"[VERSION] Python: {platform.python_version()}")

                    print(f"[VERSION] Platform: {platform.system()} {platform.release()}")

                    print(f"[VERSION] Architecture: {platform.machine()}\n")



                # PLATFORM COMMAND

                elif cmd == "platform":

                    platform_info = config_manager.get_platform_info()

                    print(f"\n[PLATFORM] Current: {platform_info['current_platform']}")

                    print(f"[PLATFORM] Supported: {', '.join(platform_info['supported_platforms'])}")

                    print(f"[PLATFORM] Cross-platform: {platform_info['cross_platform_mode']}")

                    print(f"[PLATFORM] Optimized for: {platform_info['optimized_for']}\n")



                # CONFIG COMMAND

                elif cmd == "config":

                    print(f"\n[CONFIG] Configuration file: {config_manager.path}")

                    print(f"[CONFIG] User ID: {config_manager.config.get('user_id')}")

                    print(f"[CONFIG] P2P Port: {p2p_port}")

                    print(f"[CONFIG] API Port: {api_port}")

                    print(f"[CONFIG] HTTP Enabled: {enable_http}")

                    print(f"[CONFIG] Localhost only: {config_manager.is_localhost_enforced()}\n")



                # DB-PATH COMMAND

                elif cmd == "db-path":

                    print(f"\n[DB] Database path: {node_instance.database.db_path}")

                    print(f"[DB] Database exists: {os.path.exists(node_instance.database.db_path)}")

                    if os.path.exists(node_instance.database.db_path):

                        size = os.path.getsize(node_instance.database.db_path)

                        print(f"[DB] Database size: {size} bytes ({size/1024:.2f} KB)\n")



                # CONNECT COMMAND

                elif cmd == "connect":

                    if len(cmd_parts) < 2:

                        print("[ERROR] Usage: connect <host> or connect <host:port>")

                        continue

                    

                    target = cmd_parts[1]

                    if ":" in target:

                        host, port = target.split(":")

                        port = int(port)

                    else:

                        host = target

                        port = 4000

                    

                    print(f"[CONNECT] Connecting to {host}:{port}...")

                    success = node_instance.connect_to_peer(host, port)

                    if success:

                        print(f"[CONNECT] Successfully connected to {host}:{port}")

                    else:

                        print(f"[CONNECT] Failed to connect to {host}:{port}")



                # PEERS COMMAND

                elif cmd == "peers":

                    peer_list = node_instance.get_peer_list()

                    print(f"\n[PEERS] Connected peers ({len(peer_list)}/{node_instance.max_peers}):")

                    if not peer_list:

                        print("  No peers connected")

                    else:

                        for i, peer_addr in enumerate(peer_list, 1):

                            print(f"  {i}. {peer_addr[0]}:{peer_addr[1]}")

                    print()



                # PEER-STATUS COMMAND

                elif cmd == "peer-status":

                    peer_status = node_instance.get_peer_status_info()

                    print(f"\n[PEER-STATUS] Detailed status ({len(peer_status)} peers):")

                    

                    if not peer_status:

                        print("  No peers connected")

                    else:

                        for i, (peer_addr, status) in enumerate(peer_status.items(), 1):

                            alive_status = "ALIVE" if status['is_alive'] else "TIMEOUT"

                            print(f"\n  {i}. {peer_addr}")

                            print(f"     Status: {alive_status}")

                            print(f"     Platform: {status['platform']}")

                            print(f"     User: {status['user_id'][:16]}...")

                            print(f"     Connected: {status['connected_duration']}")

                            print(f"     Last heartbeat: {status['last_heartbeat']}")

                    print()



                # NETWORK-INFO COMMAND

                elif cmd == "network-info":

                    peers = node_instance.get_peer_count()

                    peer_status = node_instance.get_peer_status_info()

                    content_log = node_instance.get_content_validation_log()

                    

                    print(f"\n[NETWORK] Connected peers: {peers}/{node_instance.max_peers}")

                    print(f"[NETWORK] Known peers: {len(node_instance.known_peers)}")

                    print(f"[NETWORK] Auto-reconnect: Active")

                    print(f"[NETWORK] Heartbeat interval: {node_instance.heartbeat_interval}s")

                    print(f"[NETWORK] Connection timeout: {node_instance.connection_timeout}s")

                    print(f"[NETWORK] Messages processed: {len(content_log)}\n")



                # KNOWN-PEERS COMMAND

                elif cmd == "known-peers":

                    print(f"\n[KNOWN-PEERS] Stored peers ({len(node_instance.known_peers)}):")

                    if not node_instance.known_peers:

                        print("  No known peers in storage")

                    else:

                        connected = set(node_instance.peers.keys())

                        for i, peer_addr in enumerate(node_instance.known_peers, 1):

                            status = "CONNECTED" if peer_addr in connected else "disconnected"

                            print(f"  {i}. {peer_addr[0]}:{peer_addr[1]} - {status}")

                    print()



                # SITES COMMAND

                elif cmd == "sites":

                    sites = node_instance.database.get_sites()

                    print(f"\n[SITES] Registered sites ({len(sites)}):")

                    if not sites:

                        print("  No sites registered")

                    else:

                        for i, site in enumerate(sites, 1):

                            print(f"\n  {i}. {site['site_name']}")

                            print(f"     Created: {site.get('created_date', 'Unknown')}")

                            print(f"     Falcon Public: {site.get('falcon_public', 'N/A')[:40]}...")

                            print(f"     Dilithium Public: {site.get('dilithium_public', 'N/A')[:40]}...")

                    print()



                # CREATE COMMAND

                elif cmd == "create":

                    if len(cmd_parts) < 2:

                        print("[ERROR] Usage: create <site_name>")

                        continue

                    

                    site_name = cmd_parts[1]

                    print(f"[CREATE] Creating site '{site_name}'...")

                    

                    # Generate keys

                    keys = node_instance.crypto.generate_site_keypair()

                    

                    # Store site

                    success = node_instance.database.store_site(

                        site_name=site_name,

                        owner_id=node_instance.crypto.crypto_id,

                        keys_data=keys

                    )

                    

                    if success:

                        print(f"[CREATE] Site '{site_name}' created successfully")

                    else:

                        print(f"[CREATE] Failed to create site '{site_name}'")



                # KEYS COMMAND

                elif cmd == "keys":

                    if len(cmd_parts) < 2:

                        print("[ERROR] Usage: keys <site_name>")

                        continue

                    

                    site_name = cmd_parts[1]

                    keys = node_instance.database.get_site_keys(site_name)

                    

                    if keys:

                        print(f"\n[KEYS] Keys for site '{site_name}':")

                        print(f"  Falcon Private: {keys.get('falcon_private', 'N/A')}")

                        print(f"  Falcon Public: {keys.get('falcon_public', 'N/A')}")

                        print(f"  Dilithium Private: {keys.get('dilithium_private', 'N/A')}")

                        print(f"  Dilithium Public: {keys.get('dilithium_public', 'N/A')}\n")

                    else:

                        print(f"[KEYS] Site '{site_name}' not found")



                # CONTENT COMMAND

                elif cmd == "content":

                    site_filter = cmd_parts[1] if len(cmd_parts) > 1 else None

                    contents = node_instance.database.get_content(site_name=site_filter, limit=50)

                    

                    print(f"\n[CONTENT] Stored content ({len(contents)} entries):")

                    if not contents:

                        print("  No content stored")

                    else:

                        for i, content in enumerate(contents[-20:], 1):

                            print(f"\n  {i}. Site: {content.get('site_name')}")

                            print(f"     Date: {content.get('date', 'Unknown')}")

                            print(f"     Content: {content.get('content', '')[:80]}...")

                            if content.get('signature'):

                                print(f"     Signature: {content['signature'][:40]}...")

                    print()



                # CONTENT-LOG COMMAND

                elif cmd == "content-log":

                    content_log = node_instance.get_content_validation_log()

                    print(f"\n[CONTENT-LOG] Validation log ({len(content_log)} entries):")

                    

                    recent = content_log[-20:] if len(content_log) > 20 else content_log

                    

                    for i, entry in enumerate(recent, 1):

                        status = "VALID" if entry['is_valid'] else "INVALID"

                        print(f"\n  {i}. [{entry['validation_time']}] {status}")

                        print(f"     Site: {entry['site_name']}")

                        print(f"     Source: {entry['source_peer']}")

                        print(f"     Content: {entry['content']}")

                    print()



                # CONTENT-VALID COMMAND

                elif cmd == "content-valid":

                    content_log = node_instance.get_content_validation_log()

                    valid = [c for c in content_log if c['is_valid']]

                    

                    print(f"\n[VALID-CONTENT] Valid messages ({len(valid)}):")

                    for i, entry in enumerate(valid[-15:], 1):

                        print(f"\n  {i}. [{entry['validation_time']}] VALID")

                        print(f"     Site: {entry['site_name']}")

                        print(f"     Content: {entry['content']}")

                    print()



                # CONTENT-INVALID COMMAND

                elif cmd == "content-invalid":

                    content_log = node_instance.get_content_validation_log()

                    invalid = [c for c in content_log if not c['is_valid']]

                    

                    print(f"\n[INVALID-CONTENT] Invalid messages ({len(invalid)}):")

                    for i, entry in enumerate(invalid[-15:], 1):

                        print(f"\n  {i}. [{entry['validation_time']}] INVALID")

                        print(f"     Site: {entry['site_name']}")

                        print(f"     Content: {entry['content']}")

                        print(f"     Reason: Signature verification failed")

                    print()



                # POST COMMAND

                elif cmd == "post":

                    if len(cmd_parts) < 3:

                        print("[ERROR] Usage: post <site_name> <message>")

                        continue

                    

                    site_name = cmd_parts[1]

                    message = " ".join(cmd_parts[2:])

                    

                    print(f"[POST] Posting to site '{site_name}'...")

                    success = node_instance.broadcast_content_to_network(site_name, message)

                    

                    if success:

                        print(f"[POST] Message posted successfully")

                    else:

                        print(f"[POST] Failed to post message")



                # BROADCAST COMMAND

                elif cmd == "broadcast":

                    if len(cmd_parts) < 3:

                        print("[ERROR] Usage: broadcast <site_name> <message>")

                        continue

                    

                    site_name = cmd_parts[1]

                    message = " ".join(cmd_parts[2:])

                    

                    print(f"[BROADCAST] Broadcasting to network...")

                    success = node_instance.broadcast_content_to_network(site_name, message)

                    

                    if success:

                        peer_count = node_instance.get_peer_count()

                        print(f"[BROADCAST] Message broadcast to {peer_count} peers")

                    else:

                        print(f"[BROADCAST] Broadcast failed")



                # SYNC COMMAND

                elif cmd == "sync":

                    if len(cmd_parts) < 2:

                        print("[ERROR] Usage: sync <site_name>")

                        continue

                    

                    site_name = cmd_parts[1]

                    print(f"[SYNC] Syncing site '{site_name}' with peers...")

                    

                    sync_msg = {

                        "type": "SYNC_REQUEST",

                        "site_name": site_name,

                        "requester_id": node_instance.crypto.crypto_id,

                        "timestamp": time.time()

                    }

                    node_instance.broadcast_to_peers(sync_msg)

                    print(f"[SYNC] Sync request sent to all peers")



                # API COMMAND

                elif cmd == "api":

                    if node_instance.enable_http:

                        print(f"\n[API] HTTP API Server Information:")

                        print(f"  URL: http://127.0.0.1:{node_instance.api_port}")

                        print(f"  Status: Active")

                        print(f"  Access: Localhost only")

                        print(f"\n  Available endpoints:")

                        print(f"    GET  /api/status")

                        print(f"    GET  /api/sites")

                        print(f"    GET  /api/content?site=<name>")

                        print(f"    POST /api/create_site")

                        print(f"    POST /api/broadcast_content\n")

                    else:

                        print("[API] HTTP API is disabled")



                # DEBUG-PEERS COMMAND

                elif cmd == "debug-peers":

                    print("\n[DEBUG] Testing localhost connection...")

                    success = node_instance.connect_to_peer("127.0.0.1", p2p_port + 1)

                    print(f"[DEBUG] Test result: {'Success' if success else 'Failed'}")

                    

                    print(f"\n[DEBUG] Current peer connections:")

                    for peer_addr in node_instance.peers.keys():

                        print(f"  - {peer_addr[0]}:{peer_addr[1]}")

                    print()



                # TEST-BROADCAST COMMAND

                elif cmd == "test-broadcast":

                    print("[TEST] Testing broadcast functionality...")

                    test_msg = {

                        "type": "TEST",

                        "message": "Test broadcast message",

                        "timestamp": time.time()

                    }

                    node_instance.broadcast_to_peers(test_msg)

                    peer_count = node_instance.get_peer_count()

                    print(f"[TEST] Test message broadcast to {peer_count} peers")



                # UNKNOWN COMMAND

                else:

                    print(f"\n[ERROR] Unknown command: '{cmd}'")

                    print("[HELP] Type 'help' to see all available commands\n")



            except EOFError:

                print("\n[SHUTDOWN] EOF received, stopping node...")

                break

            except KeyboardInterrupt:

                print("\n[SHUTDOWN] Keyboard interrupt, stopping node...")

                break

            except Exception as e:

                print(f"[ERROR] Command error: {e}")

                import traceback

                traceback.print_exc()



    except Exception as e:

        print(f"[ERROR] Initialization failed: {e}")

        import traceback

        traceback.print_exc()

        return 1

    

    finally:

        if node_instance:

            try:

                node_instance.shutdown()

            except Exception as e:

                print(f"[SHUTDOWN] Cleanup error: {e}")

        

        print("[SHUTDOWN] Node stopped successfully")

    

    return 0



if __name__ == "__main__":

    sys.exit(main())

 