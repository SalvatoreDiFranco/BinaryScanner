import pyfiglet
import argparse
from colorama import init, Fore, Style

init(autoreset=True)

from rules.bof_rule import check as check_bof
from rules.fsb_rule import check as check_fsb
from rules.uaf_rule import check as check_uaf

def display_banner():
    result = pyfiglet.figlet_format("BinaryScanner", font="slant")
    print(f"{Fore.BLUE}{result}::: A tool to detect vulnerabilities in executable files! :::\n{Style.RESET_ALL}")

def display_help():
    print(f"Usage: python binary_scanner.py [options]{Style.RESET_ALL}")
    print(f"{Fore.BLUE}Options:{Style.RESET_ALL}")
    print(f"  {Fore.BLUE}--file [FILEPATH]{Style.RESET_ALL}  Specify the binary file to scan")
    print(f"  {Fore.BLUE}--bof{Style.RESET_ALL}              Scan for Buffer Overflow (BOF)")
    print(f"  {Fore.BLUE}--fsb{Style.RESET_ALL}              Scan for Format String Bug (FSB)")
    print(f"  {Fore.BLUE}--uaf{Style.RESET_ALL}              Scan for Use After Free (UAF)")
    print(f"  {Fore.BLUE}--df{Style.RESET_ALL}               Scan for Double Free (DF)")
    print(f"  {Fore.BLUE}-v, --version{Style.RESET_ALL}      Show the version of BinaryScanner\n")

def parse_args():
    parser = argparse.ArgumentParser(description='BinaryScanner CLI Tool')
    parser.add_argument('--file', metavar='FILEPATH', type=str, help='Specify the binary file to scan')
    parser.add_argument('--bof', action='store_true', help='Scan for Buffer Overflow (BOF)')
    parser.add_argument('--fsb', action='store_true', help='Scan for Format String Bug (FSB)')
    parser.add_argument('--uaf', action='store_true', help='Scan for Use After Free (UAF)')
    parser.add_argument('--df', action='store_true', help='Scan for Double Free (DF)')
    parser.add_argument('-v', '--version', action='store_true', help='Show the version of BinaryScanner')
    return parser.parse_args()

def scan_vulnerability(filepath, vuln_type):
    if vuln_type == 'bof':
        print(f"{Fore.YELLOW}Scanning {filepath} for Buffer Overflow (BOF)...{Style.RESET_ALL}")
        check_bof(filepath)
        print()
    elif vuln_type == 'fsb':
        print(f"{Fore.YELLOW}Scanning {filepath} for Format String Bug (FSB)...{Style.RESET_ALL}")
        check_fsb(filepath)
        print()
    elif vuln_type == 'uaf':
        print(f"{Fore.YELLOW}Scanning {filepath} for Use After Free (UAF)...{Style.RESET_ALL}")
        check_uaf(filepath)
        print()
    elif vuln_type == 'df':
        print(f"{Fore.YELLOW}Scanning {filepath} for Double Free (DF)...{Style.RESET_ALL}")
        check_uaf(filepath)
        print()

def main():
    display_banner()
    args = parse_args()

    if args.version:
        print(f"{Fore.CYAN}BinaryScanner version 1.0{Style.RESET_ALL}\n")
    elif not args.file:
        print(f"{Fore.RED}Error: You must specify a file to scan using --file{Style.RESET_ALL}\n")
        display_help()
    else:
        if args.bof:
            scan_vulnerability(args.file, 'bof')
        elif args.fsb:
            scan_vulnerability(args.file, 'fsb')
        elif args.uaf:
            scan_vulnerability(args.file, 'uaf')
        elif args.df:
            scan_vulnerability(args.file, 'df')
        else:
            print(f"{Fore.RED}Please specify a vulnerability type to scan (--bof, --fsb, --uaf, --df){Style.RESET_ALL}\n")
            display_help()

if __name__ == '__main__':
    main()
