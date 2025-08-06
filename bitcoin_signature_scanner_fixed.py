#!/usr/bin/env python3
"""Bitcoin Signature Scanner and Analyzer
This script automatically scans Bitcoin blockchain via Chainstack,
gathers signatures, stores them in a SQLite database, and analyzes for vulnerabilities.
Debug version with additional output and proper RPC verbosity."""

import os
import sys
import time
import json
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
from whole_tool import ECDSAAffineAttack, SignatureData, ChainAnalysisResult


class SignatureDatabase:
    """Handles storage and retrieval of signatures and analysis results"""
    
    def __init__(self, db_path: str = "signatures.db"):
        print(f"Initializing SignatureDatabase with path: {db_path}")
        self.db_path = db_path
        self.init_database()
        
    def init_database(self):
        """Initialize database schema"""
        print("Creating or verifying database tables...")
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create signatures table
            print("- Creating signatures table")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tx_hash TEXT,
                    block_number INTEGER,
                    r_value TEXT,
                    s_value TEXT,
                    message_hash TEXT,
                    from_address TEXT,
                    script_type TEXT,
                    signature_type TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create vulnerabilities table
            print("- Creating vulnerabilities table")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vulnerability_type TEXT,
                    severity TEXT,
                    description TEXT,
                    affected_signatures TEXT,  -- JSON array of signature IDs
                    recovered_key TEXT,
                    affine_params TEXT,  -- JSON string of [a, b]
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create analysis_runs table
            print("- Creating analysis_runs table")
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_block INTEGER,
                    end_block INTEGER,
                    signatures_analyzed INTEGER,
                    vulnerabilities_found INTEGER,
                    duration_seconds FLOAT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
        print("Database tables created successfully")

    def store_signature(self, sig: SignatureData):
        """Store a signature in the database"""
        print(f"Storing signature from tx: {sig.tx_hash[:10]}...")
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO signatures (
                        tx_hash, block_number, r_value, s_value,
                        message_hash, from_address, script_type, signature_type
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    sig.tx_hash,
                    sig.block_number,
                    hex(sig.r),
                    hex(sig.s),
                    hex(sig.message_hash),
                    sig.from_address,
                    sig.script_type,
                    sig.signature_type
                ))
                conn.commit()
            print("Signature stored successfully")
        except Exception as e:
            print(f"Error storing signature: {e}")

    def store_vulnerability(self, vuln: Dict[str, Any]):
        """Store a detected vulnerability"""
        print("Processing vulnerability...")
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Convert signature objects to IDs or relevant data
                affected_sigs = []
                for sig in vuln.get('signatures', []):
                    cursor.execute(
                        "SELECT id FROM signatures WHERE tx_hash = ?",
                        (sig.tx_hash,)
                    )
                    sig_id = cursor.fetchone()
                    if sig_id:
                        affected_sigs.append(sig_id[0])
                
                cursor.execute("""
                    INSERT INTO vulnerabilities (
                        vulnerability_type, severity, description,
                        affected_signatures, recovered_key, affine_params
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    vuln['type'],
                    vuln['severity'],
                    vuln['description'],
                    json.dumps(affected_sigs),
                    vuln.get('recovered_key'),
                    json.dumps(vuln.get('affine_params'))
                ))
                conn.commit()
            print(f"Stored vulnerability affecting {len(affected_sigs)} signatures")
        except Exception as e:
            print(f"Error storing vulnerability: {e}")

    def store_analysis_run(self, start_block: int, end_block: int,
                         signatures_analyzed: int, vulnerabilities_found: int,
                         duration: float):
        """Store analysis run metadata"""
        print(f"Recording analysis run: blocks {start_block}-{end_block}")
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO analysis_runs (
                        start_block, end_block, signatures_analyzed,
                        vulnerabilities_found, duration_seconds
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    start_block, end_block, signatures_analyzed,
                    vulnerabilities_found, duration
                ))
                conn.commit()
            print("Analysis run recorded successfully")
        except Exception as e:
            print(f"Error recording analysis run: {e}")

    def get_last_analyzed_block(self) -> Optional[int]:
        """Get the last analyzed block number"""
        print("Checking last analyzed block...")
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT MAX(end_block) FROM analysis_runs"
                )
                result = cursor.fetchone()
                last_block = result[0] if result and result[0] is not None else None
                print(f"Last analyzed block: {last_block}")
                return last_block
        except Exception as e:
            print(f"Error checking last block: {e}")
            return None


class BitcoinSignatureScanner:
    """Main scanner class that coordinates the signature gathering and analysis"""
    
    def __init__(self, chainstack_url: str, api_key: Optional[str] = None,
                 db_path: str = "signatures.db", batch_size: int = 50):
        print("Initializing Bitcoin Signature Scanner...")
        print(f"Chainstack URL: {chainstack_url}")
        self.attack = ECDSAAffineAttack(chainstack_url=chainstack_url,
                                      chainstack_api_key=api_key)
        print("ECDSAAffineAttack initialized")
        self.db = SignatureDatabase(db_path)
        self.batch_size = batch_size
        self.start_block = 550000  # Start from block 550000
        print(f"Scanner configured with batch size {batch_size}, start block {self.start_block}")
    
    def scan_new_blocks(self):
        """Scan new blocks since last analysis"""
        try:
            print("\nStarting block scan...")
            print("Getting latest block number from chain...")
            
            # Get latest block from chain
            latest_block = self.attack.chainstack_client.get_latest_block_number()
            current_block = self.start_block
            
            print(f"Latest block on chain: {latest_block}")
            print(f"Current block pointer: {current_block}")
            
            if latest_block <= current_block:
                print(f"No blocks to analyze after block {current_block}")
                return
            
            print(f"Starting analysis from block {self.start_block}")
            print(f"Will scan blocks {self.start_block} to {latest_block}")
            start_time = time.time()
            
            # Analyze in batches
            for batch_start in range(self.start_block, latest_block + 1, self.batch_size):
                batch_end = min(batch_start + self.batch_size - 1, latest_block)
                
                print(f"\nProcessing batch: blocks {batch_start}-{batch_end}")
                print("Getting block data...")
                
                # Analyze blockchain data
                result = self.attack.analyze_blockchain_signatures(
                    block_range=(batch_start, batch_end),
                    search_affine_relationships=True
                )
                
                print(f"Got data for {result.blocks_analyzed} blocks")
                print(f"Found {result.signatures_extracted} signatures")
                print(f"Found {len(result.potential_vulnerabilities)} vulnerabilities")
                
                # Store signatures and vulnerabilities
                self._process_analysis_result(result)
                
                # Store analysis run data
                duration = time.time() - start_time
                self.db.store_analysis_run(
                    batch_start, batch_end,
                    result.signatures_extracted,
                    len(result.potential_vulnerabilities),
                    duration
                )
                
                print(f"Batch complete.")
                print(f"Total signatures in batch: {result.signatures_extracted}")
                print(f"Total vulnerabilities in batch: {len(result.potential_vulnerabilities)}")
                
                # Optional delay between batches
                print("Sleeping 1 second before next batch...")
                time.sleep(1)
                
        except Exception as e:
            print(f"Error during scanning: {e}")
            import traceback
            traceback.print_exc()
            raise

    def _process_analysis_result(self, result: ChainAnalysisResult):
        """Process and store analysis results"""
        print("\nProcessing analysis results...")
        try:
            # Store all extracted signatures
            sig_count = 0
            vuln_count = 0
            
            for vuln in result.potential_vulnerabilities:
                print(f"\nProcessing vulnerability type: {vuln['type']}")
                for sig in vuln.get('signatures', []):
                    print(f"- Storing signature {sig_count + 1} from tx: {sig.tx_hash[:10]}")
                    self.db.store_signature(sig)
                    sig_count += 1
                print("Storing vulnerability record...")
                self.db.store_vulnerability(vuln)
                vuln_count += 1
                
            print(f"\nProcessed {sig_count} signatures")
            print(f"Processed {vuln_count} vulnerabilities")
        
        except Exception as e:
            print(f"Error processing results: {e}")
            import traceback
            traceback.print_exc()

    def run_continuous_scan(self, interval_seconds: int = 600):
        """Run continuous scanning with specified interval"""
        print(f"\nStarting continuous scan with {interval_seconds}s interval")
        
        while True:
            try:
                print(f"\nScan cycle started at {datetime.now()}")
                self.scan_new_blocks()
                print(f"\nSleeping for {interval_seconds} seconds...")
                time.sleep(interval_seconds)
                
            except KeyboardInterrupt:
                print("\nStopping continuous scan...")
                break
            except Exception as e:
                print(f"\nError in scan cycle: {e}")
                print("Retrying in 60 seconds...")
                time.sleep(60)


def main():
    """Main entry point"""
    # Configuration
    CHAINSTACK_URL = os.getenv("CHAINSTACK_URL")
    CHAINSTACK_API_KEY = os.getenv("CHAINSTACK_API_KEY")
    DB_PATH = os.getenv("DB_PATH", "signatures.db")
    SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "600"))
    
    if not CHAINSTACK_URL:
        print("Error: CHAINSTACK_URL environment variable is required")
        sys.exit(1)
    
    print("\n=== Bitcoin Signature Scanner (Debug Version) ===")
    print(f"Database path: {DB_PATH}")
    print(f"Scan interval: {SCAN_INTERVAL}s")
    
    scanner = BitcoinSignatureScanner(
        chainstack_url=CHAINSTACK_URL,
        api_key=CHAINSTACK_API_KEY,
        db_path=DB_PATH,
        batch_size=50  # Smaller batch size to handle full transaction data
    )
    
    print("\nStarting scan process...")
    scanner.run_continuous_scan(interval_seconds=SCAN_INTERVAL)


if __name__ == "__main__":
    main()
