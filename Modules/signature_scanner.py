"""
Signature Scanner Module - YARA-based Ransomware Detection
Integrates signature-based detection for known ransomware families using YARA rules.

FEATURES:
- Loads and compiles YARA rules from a directory
- Scans process executables for matches
- Supports commoditized and HoR ransomware signatures
- Low-overhead scanning on process creation

DEPENDENCIES:
- yara-python (pip install yara-python)

RULE SOURCES:
- Incorporated samples from public repositories (ReversingLabs, etc.)
- Expand by adding .yar files to 'rules/' directory
- Update rules quarterly from sources like:
  - https://github.com/reversinglabs/reversinglabs-yara-rules
  - https://github.com/advanced-threat-research/Yara-Rules
  - https://github.com/Yara-Rules/rules
  - Malpedia, Ransomware.live

USAGE:
scanner = SignatureScanner(rules_dir='rules/')
hits = scanner.scan(executable_path)
"""

import io
import os
import logging
from pathlib import Path
from typing import List, Optional, Dict
import sys

# Check for yara-python availability
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("WARNING: yara-python not installed. Install with: pip install yara-python")



# Fix Windows console encoding issues
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except AttributeError:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

class SignatureScanner:
    """
    YARA-based scanner for ransomware signatures.
    
    MAINTENANCE:
    - Add new .yar files to rules_dir for emerging threats
    - Compile once at init for performance
    - Handle large files via timeout (configurable)
    """
    
    def __init__(self, rules_dir: str = 'rules/', timeout: int = 30, verbose: bool = False):
        self.rules_dir = Path(rules_dir)
        self.timeout = timeout
        self.verbose = verbose
        self.compiled_rules: Optional['yara.Rules'] = None
        self.compilation_errors: List[str] = []
        self.rule_count = 0
        self._setup_logging()
        
        if not YARA_AVAILABLE:
            self.logger.error("YARA module not available. Please install: pip install yara-python")
            return
            
        self._compile_rules()
    
    def _setup_logging(self):
        """Configure logging."""
        log_level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger("SignatureScanner")
    
    def _compile_rules(self):
        """Compile all .yar files in rules_dir."""
        if not YARA_AVAILABLE:
            return
            
        # Create rules directory if it doesn't exist
        if not self.rules_dir.exists():
            self.logger.info(f"Creating rules directory: {self.rules_dir}")
            self.rules_dir.mkdir(parents=True, exist_ok=True)
            self._create_sample_rules()
        
        # Find all .yar files
        rule_files = {}
        for yar_file in self.rules_dir.glob('*.yar'):
            if yar_file.is_file():
                namespace = str(yar_file.stem)
                rule_files[namespace] = str(yar_file)
                self.logger.debug(f"Found rule file: {yar_file.name}")
        
        if not rule_files:
            self.logger.warning(f"No YARA rules found in {self.rules_dir}")
            self.logger.warning("Creating sample rules...")
            self._create_sample_rules()
            # Try again after creating sample rules
            for yar_file in self.rules_dir.glob('*.yar'):
                if yar_file.is_file():
                    namespace = str(yar_file.stem)
                    rule_files[namespace] = str(yar_file)
        
        if not rule_files:
            self.logger.error("Still no YARA rules available after creating samples")
            return
        
        # Compile rules with detailed error handling
        try:
            self.logger.info(f"Compiling {len(rule_files)} YARA rule file(s)...")
            
            # Validate each rule file before compilation
            valid_rules = {}
            for namespace, filepath in rule_files.items():
                try:
                    # Test compile individual file
                    with open(filepath, 'r', encoding='utf-8') as f:
                        rule_content = f.read()
                    
                    # Try to compile this specific rule
                    test_compile = yara.compile(source=rule_content)
                    valid_rules[namespace] = filepath
                    self.logger.debug(f"  [OK] {namespace}: Valid")
                    
                except yara.SyntaxError as e:
                    error_msg = f"{namespace}: Syntax error - {e}"
                    self.compilation_errors.append(error_msg)
                    self.logger.error(f"  [FAIL] {error_msg}")
                except Exception as e:
                    error_msg = f"{namespace}: Error - {e}"
                    self.compilation_errors.append(error_msg)
                    self.logger.error(f"  [FAIL] {error_msg}")
            
            # Compile all valid rules together
            if valid_rules:
                self.compiled_rules = yara.compile(filepaths=valid_rules)
                self.rule_count = len(valid_rules)
                self.logger.info(f"Successfully compiled {self.rule_count} rule file(s): {', '.join(valid_rules.keys())}")
            else:
                self.logger.error("No valid YARA rules to compile")
                
        except yara.SyntaxError as e:
            error_msg = f"YARA syntax error during compilation: {e}"
            self.compilation_errors.append(error_msg)
            self.logger.error(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during compilation: {e}"
            self.compilation_errors.append(error_msg)
            self.logger.error(error_msg)
    
    def _create_sample_rules(self):
        """Create sample YARA rules files if directory is empty."""
        
        # Sample 1: Basic ransomware indicators
        basic_rules = """
/*
    Basic Ransomware Indicators
    These are simplified patterns for testing purposes
*/

rule Ransomware_Generic_ShadowCopy_Command
{
    meta:
        description = "Detects shadow copy deletion commands in executables"
        author = "Security Team"
        severity = "high"
        category = "ransomware"
    
    strings:
        $cmd1 = "vssadmin delete shadows" ascii wide nocase
        $cmd2 = "wmic shadowcopy delete" ascii wide nocase
        $cmd3 = "delete shadows /all" ascii wide nocase
        
    condition:
        any of them
}

rule Ransomware_Generic_Bootconfig
{
    meta:
        description = "Detects boot configuration manipulation"
        author = "Security Team"
        severity = "high"
        category = "ransomware"
    
    strings:
        $bcdedit1 = "bcdedit" ascii wide nocase
        $bcdedit2 = "recoveryenabled" ascii wide nocase
        $bcdedit3 = "bootstatuspolicy" ascii wide nocase
        
    condition:
        $bcdedit1 and ($bcdedit2 or $bcdedit3)
}

rule Ransomware_Generic_FileExtensions
{
    meta:
        description = "Detects common ransomware file extensions"
        author = "Security Team"
        severity = "medium"
        category = "ransomware"
    
    strings:
        $ext1 = ".locked" ascii wide
        $ext2 = ".encrypted" ascii wide
        $ext3 = ".crypto" ascii wide
        $ext4 = ".crypt" ascii wide
        $ext5 = ".lockbit" ascii wide
        $ext6 = ".ryuk" ascii wide
        
    condition:
        2 of them
}
"""
        
        # Sample 2: Known ransomware families (simplified)
        family_rules = """
/*
    Known Ransomware Family Signatures
    Simplified versions for detection testing
*/

rule Win32_Ransomware_LockBit_Indicator
{
    meta:
        description = "LockBit ransomware indicators"
        author = "Security Team"
        malware = "LockBit"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $str1 = "LockBit" ascii wide nocase
        $str2 = ".lockbit" ascii wide nocase
        $str3 = "Restore-My-Files" ascii wide nocase
        $cmd1 = "vssadmin delete shadows /all /quiet" ascii wide
        
    condition:
        any of ($str*) or any of ($cmd*)
}

rule Win32_Ransomware_Ryuk_Indicator
{
    meta:
        description = "Ryuk ransomware indicators"
        author = "Security Team"
        malware = "Ryuk"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $str1 = "RYUK" ascii wide
        $str2 = "RyukReadMe" ascii wide nocase
        $str3 = ".RYK" ascii wide
        $net = "net stop" ascii wide
        
    condition:
        any of ($str*) or $net
}

rule Win32_Ransomware_Conti_Indicator
{
    meta:
        description = "Conti ransomware indicators"
        author = "Security Team"
        malware = "Conti"
        severity = "critical"
        category = "ransomware"
    
    strings:
        $str1 = "CONTI" ascii wide
        $str2 = "CONTI_LOG" ascii wide
        $readme = "readme.txt" ascii wide nocase
        
    condition:
        2 of them
}
"""
        
        # Sample 3: Behavior-based detection
        behavior_rules = """
/*
    Behavior-based Ransomware Detection
    Detects suspicious executable patterns
*/

rule Ransomware_Behavior_MassFileEncryption
{
    meta:
        description = "Detects crypto APIs commonly used for file encryption"
        author = "Security Team"
        severity = "high"
        category = "ransomware_behavior"
    
    strings:
        $crypto1 = "CryptEncrypt" ascii
        $crypto2 = "CryptAcquireContext" ascii
        $crypto3 = "CryptGenKey" ascii
        $crypto4 = "CryptCreateHash" ascii
        $file1 = "CreateFile" ascii
        $file2 = "WriteFile" ascii
        
    condition:
        2 of ($crypto*) and 2 of ($file*)
}

rule Ransomware_Behavior_NetworkBeacon
{
    meta:
        description = "Detects C2 communication patterns"
        author = "Security Team"
        severity = "medium"
        category = "ransomware_behavior"
    
    strings:
        $http1 = "POST" ascii
        $http2 = "User-Agent:" ascii
        $tor = ".onion" ascii
        $encrypt = "AES" ascii nocase
        
    condition:
        ($http1 and $http2) or $tor or $encrypt
}
"""
        
        # Write the sample rule files
        samples = {
            'basic_ransomware.yar': basic_rules,
            'ransomware_families.yar': family_rules,
            'ransomware_behaviors.yar': behavior_rules
        }
        
        for filename, content in samples.items():
            rule_path = self.rules_dir / filename
            try:
                rule_path.write_text(content, encoding='utf-8')
                self.logger.info(f"Created sample rules file: {rule_path}")
            except Exception as e:
                self.logger.error(f"Failed to create {filename}: {e}")

    def scan(self, file_path: Optional[str]) -> List[str]:
        """
        Scan a file for ransomware signatures.
        
        Args:
            file_path: Path to executable to scan (from ProcessEvent.executable_path)
        
        Returns:
            List of matched rule names (e.g., ['Win32_Ransomware_LockBit_Indicator'])
        """
        if not YARA_AVAILABLE:
            self.logger.debug("YARA not available, skipping scan")
            return []
            
        if not self.compiled_rules:
            self.logger.debug("No compiled rules available. Skipping scan.")
            return []
        
        if not file_path:
            self.logger.debug("No file path provided")
            return []
            
        file_obj = Path(file_path)
        if not file_obj.exists():
            self.logger.debug(f"File does not exist: {file_path}")
            return []
        
        if not file_obj.is_file():
            self.logger.debug(f"Not a file: {file_path}")
            return []
        
        try:
            # Scan the file
            matches = self.compiled_rules.match(filepath=str(file_obj), timeout=self.timeout)
            
            # Extract rule names and metadata
            hit_rules = []
            for match in matches:
                rule_name = match.rule
                hit_rules.append(rule_name)
                
                # Log with metadata if available
                if match.meta:
                    severity = match.meta.get('severity', 'unknown')
                    malware = match.meta.get('malware', 'unknown')
                    self.logger.warning(
                        f"SIGNATURE HIT: {rule_name} | File: {file_path} | "
                        f"Malware: {malware} | Severity: {severity}"
                    )
                else:
                    self.logger.warning(f"SIGNATURE HIT: {rule_name} | File: {file_path}")
            
            return hit_rules
            
        except yara.TimeoutError:
            self.logger.error(f"Scan timeout (>{self.timeout}s) for {file_path}")
            return []
        except yara.Error as e:
            self.logger.error(f"YARA error scanning {file_path}: {e}")
            return []
        except PermissionError:
            self.logger.debug(f"Permission denied accessing {file_path}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error scanning {file_path}: {e}")
            return []
    
    def get_status(self) -> Dict[str, any]:
        """Get scanner status and statistics."""
        return {
            'yara_available': YARA_AVAILABLE,
            'rules_compiled': self.compiled_rules is not None,
            'rule_count': self.rule_count,
            'rules_directory': str(self.rules_dir),
            'compilation_errors': self.compilation_errors,
            'timeout': self.timeout
        }
    
    def print_status(self):
        """Print human-readable status information."""
        status = self.get_status()
        
        print("\n" + "="*70)
        print("SIGNATURE SCANNER STATUS")
        print("="*70)
        print(f"YARA Available:      {status['yara_available']}")
        print(f"Rules Compiled:      {status['rules_compiled']}")
        print(f"Active Rules:        {status['rule_count']}")
        print(f"Rules Directory:     {status['rules_directory']}")
        print(f"Scan Timeout:        {status['timeout']}s")
        
        if status['compilation_errors']:
            print(f"\nCompilation Errors:  {len(status['compilation_errors'])}")
            for error in status['compilation_errors']:
                print(f"  - {error}")
        else:
            print(f"\nCompilation Errors:  None")
        
        print("="*70 + "\n")


# Example usage and testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="YARA-based Ransomware Signature Scanner")
    parser.add_argument('--file', type=str, help='File to scan')
    parser.add_argument('--rules-dir', type=str, default='rules/', help='Directory containing YARA rules')
    parser.add_argument('--status', action='store_true', help='Print scanner status')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--test', action='store_true', help='Run self-test')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = SignatureScanner(rules_dir=args.rules_dir, verbose=args.verbose)
    
    # Print status if requested
    if args.status or args.test:
        scanner.print_status()
    
    # Scan file if provided
    if args.file:
        print(f"\nScanning: {args.file}")
        hits = scanner.scan(args.file)
        if hits:
            print(f"\n[!] MATCHES FOUND: {len(hits)}")
            for hit in hits:
                print(f"  - {hit}")
        else:
            print("\n[OK] No signature matches")
    
    # Run self-test if requested
    if args.test:
        print("\n" + "="*70)
        print("RUNNING SELF-TEST")
        print("="*70)
        
        # Test with Python executable itself
        test_file = sys.executable
        print(f"\nTest scan: {test_file}")
        hits = scanner.scan(test_file)
        print(f"Results: {len(hits)} matches")
        
        # Test with non-existent file
        print(f"\nTest scan: nonexistent_file.exe")
        hits = scanner.scan("nonexistent_file.exe")
        print(f"Results: {len(hits)} matches (should be 0)")
        
        print("\n" + "="*70)
        print("SELF-TEST COMPLETE")
        print("="*70 + "\n")
    
    if not (args.file or args.status or args.test):
        parser.print_help()
