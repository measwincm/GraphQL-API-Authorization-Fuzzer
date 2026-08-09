#!/usr/bin/env python3
"""
Enhanced CLI for GraphQL AuthZ Fuzzer
Interactive mode with progress bars
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import json
import time
from datetime import datetime
from graphql_authz_fuzzer import GraphQLAuthzFuzzer

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    """Print progress bar to console"""
    percent = (iteration / total) * 100
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent:.1f}% {suffix}')
    sys.stdout.flush()

def interactive_scan():
    """Interactive mode for scanning"""
    print("\n" + "="*60)
    print("🔍 GraphQL AuthZ Fuzzer - Interactive Mode")
    print("="*60 + "\n")
    
    url = input("GraphQL endpoint URL: ").strip()
    token = input("Restricted token: ").strip()
    baseline = input("Baseline token (optional): ").strip() or None
    public = input("Public mutations (comma-separated, optional): ").strip()
    
    public_mutations = [m.strip() for m in public.split(',') if m.strip()] if public else []
    
    print("\n🚀 Starting scan...\n")
    
    fuzzer = GraphQLAuthzFuzzer(
        url=url,
        restricted_token=token,
        baseline_token=baseline,
        public_mutations=public_mutations,
        timeout=8,
        retries=1,
        workers=4
    )
    
    print("🔎 Discovering mutations...")
    fields = fuzzer.discover_mutations()
    
    if not fields:
        print("❌ No mutations found!")
        return
    
    print(f"✅ Found {len(fields)} mutations\n")
    
    results = []
    total = len(fields)
    
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(fuzzer.test_mutation, f): f for f in fields}
        
        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            results.append(result)
            print_progress_bar(i, total, prefix='Testing:', suffix=f'Current: {result.mutation}')
    
    print("\n\n" + "="*60)
    print("📊 RESULTS SUMMARY")
    print("="*60)
    
    critical = [r for r in results if r.severity == "Critical"]
    high = [r for r in results if r.severity == "High"]
    secure = [r for r in results if r.severity == "Secure"]
    
    print(f"\nTotal Mutations: {len(results)}")
    print(f"🔴 Critical: {len(critical)}")
    print(f"🟠 High: {len(high)}")
    print(f"🟢 Secure: {len(secure)}")
    print(f"ℹ️  Info: {len(results) - len(critical) - len(high) - len(secure)}")
    
    if critical:
        print("\n⚠️ CRITICAL VULNERABILITIES:")
        for r in critical:
            print(f"  → {r.mutation}: {r.detail}")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_results_{timestamp}.json"
    
    with open(filename, 'w') as f:
        json.dump({
            'target': url,
            'timestamp': datetime.now().isoformat(),
            'results': [r.to_dict() for r in results]
        }, f, indent=2)
    
    print(f"\n✅ Results saved to: {filename}")

def main():
    parser = argparse.ArgumentParser(description="GraphQL AuthZ Fuzzer - Enhanced CLI")
    parser.add_argument('--interactive', '-i', action='store_true', 
                       help='Run in interactive mode')
    parser.add_argument('--url', help='GraphQL endpoint URL')
    parser.add_argument('--token', help='Restricted token')
    parser.add_argument('--baseline', help='Baseline token')
    parser.add_argument('--public', help='Public mutations (comma-separated)')
    parser.add_argument('--html', default='report.html', help='HTML output file')
    parser.add_argument('--json', default='report.json', help='JSON output file')
    parser.add_argument('--csv', default='report.csv', help='CSV output file')
    parser.add_argument('--workers', type=int, default=4, help='Concurrent workers')
    
    args = parser.parse_args()
    
    if args.interactive or not args.url:
        interactive_scan()
        return
    
    from graphql_authz_fuzzer import GraphQLAuthzFuzzer
    from graphql_authz_fuzzer import generate_html_report, generate_json_report, generate_csv_report
    
    public_mutations = [m.strip() for m in args.public.split(',') if m.strip()] if args.public else []
    
    fuzzer = GraphQLAuthzFuzzer(
        url=args.url,
        restricted_token=args.token,
        baseline_token=args.baseline,
        public_mutations=public_mutations,
        workers=args.workers
    )
    
    print(f"🔍 Scanning {args.url}...")
    fields, results = fuzzer.run()
    
    print(f"✅ Found {len(fields)} mutations, tested {len(results)}")
    
    generate_html_report(args.url, results, args.html)
    generate_json_report(results, args.json)
    generate_csv_report(results, args.csv)
    
    print(f"\n📄 Reports: {args.html}, {args.json}, {args.csv}")

if __name__ == "__main__":
    main()
