import streamlit as st
import sys
import os
import json
import subprocess
from pathlib import Path
from web_exploitation.ssti import SSTIScanner
from web_exploitation.osint import OSINTScanner
from datetime import datetime
from typing import Dict

# Set page config
st.set_page_config(
    page_title="Cyber Security Tools Suite",
    page_icon="🔒",
    layout="wide"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton>button {
        width: 100%;
    }
    .report-box {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        margin: 10px 0;
    }
    .tool-header {
        color: #1E88E5;
        margin-bottom: 1rem;
    }
    .dork-box {
        background-color: #ffffff;
        padding: 15px;
        border-radius: 5px;
        margin: 5px 0;
        border: 1px solid #e0e0e0;
    }
    .dork-url {
        color: #1E88E5;
        word-break: break-all;
    }
    </style>
    """, unsafe_allow_html=True)

# Load payloads from external tools
def load_payloads():
    payloads = {
        'ssti': [],
        'ssrf': [],
        'xss': [],
        'sql': []
    }
    
    # Load SSTI payloads
    ssti_path = Path('external_tools/ssti-payloads')
    if ssti_path.exists():
        for file in ssti_path.glob('*.txt'):
            with open(file, 'r', encoding='utf-8') as f:
                payloads['ssti'].extend(f.read().splitlines())
    
    # Load SSRF payloads
    ssrf_path = Path('external_tools/PayloadsAllTheThings/Server Side Request Forgery')
    if ssrf_path.exists():
        for file in ssrf_path.glob('*.txt'):
            with open(file, 'r', encoding='utf-8') as f:
                payloads['ssrf'].extend(f.read().splitlines())
    
    return payloads

def run_ssti_scan(url, cookies, headers, payloads):
    try:
        scanner = SSTIScanner(url, cookies=cookies, headers=headers)
        results = scanner.scan_url()
        return scanner.generate_report(results)
    except Exception as e:
        return f"Error during scan: {str(e)}"

def run_osint_scan(target: str, shodan_api_key: str = None) -> Dict:
    """Run OSINT scan on the target"""
    try:
        scanner = OSINTScanner(target, shodan_api_key)
        return scanner.run_all_scans()
    except Exception as e:
        st.error(f"Error during OSINT scan: {e}")
        return {}

def run_ffuf_scan(url, wordlist, extensions):
    try:
        cmd = ['ffuf', '-u', f'{url}/FUZZ', '-w', wordlist]
        if extensions:
            cmd.extend(['-e', extensions])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return f"Error during ffuf scan: {str(e)}"

def generate_google_dorks(target):
    """Generate Google dorks for the target"""
    dorks = {
        "Site Search": [
            f'site:{target}',
            f'site:{target} inurl:admin',
            f'site:{target} inurl:login',
            f'site:{target} inurl:wp-content',
            f'site:{target} inurl:wp-admin',
            f'site:{target} inurl:administrator',
            f'site:{target} inurl:phpmyadmin',
            f'site:{target} inurl:server-status',
            f'site:{target} inurl:config'
        ],
        "File Types": [
            f'site:{target} filetype:pdf',
            f'site:{target} filetype:doc',
            f'site:{target} filetype:docx',
            f'site:{target} filetype:xls',
            f'site:{target} filetype:xlsx',
            f'site:{target} filetype:txt',
            f'site:{target} filetype:csv',
            f'site:{target} filetype:sql',
            f'site:{target} filetype:log'
        ],
        "Configuration Files": [
            f'site:{target} ext:env',
            f'site:{target} ext:config',
            f'site:{target} ext:conf',
            f'site:{target} ext:ini',
            f'site:{target} ext:xml',
            f'site:{target} ext:json',
            f'site:{target} ext:yaml',
            f'site:{target} ext:yml'
        ],
        "Sensitive Information": [
            f'site:{target} intext:"password"',
            f'site:{target} intext:"username"',
            f'site:{target} intext:"api key"',
            f'site:{target} intext:"secret"',
            f'site:{target} intext:"token"',
            f'site:{target} intext:"credential"',
            f'site:{target} intext:"private"',
            f'site:{target} intext:"confidential"'
        ],
        "Directory Listings": [
            f'site:{target} intext:"index of"',
            f'site:{target} intext:"directory listing"',
            f'site:{target} intext:"parent directory"',
            f'site:{target} intext:"last modified"'
        ],
        "Error Messages": [
            f'site:{target} intext:"error" intext:"warning"',
            f'site:{target} intext:"exception"',
            f'site:{target} intext:"stack trace"',
            f'site:{target} intext:"debug"'
        ]
    }
    return dorks

def main():
    st.title("🔒 Cyber Security Tools Suite")
    
    # Initialize session state for storing scan results
    if 'osint_results' not in st.session_state:
        st.session_state.osint_results = None
    if 'google_dorks' not in st.session_state:
        st.session_state.google_dorks = None
    if 'github_dorks' not in st.session_state:
        st.session_state.github_dorks = None
    
    # Sidebar for tool selection
    st.sidebar.title("Tools")
    tool = st.sidebar.selectbox(
        "Select Tool",
        ["SSTI Scanner", "SSRF Scanner", "Directory Fuzzer", "OSINT Scanner", 
         "Google Dorks", "GitHub Dorks"]
    )
    
    # Main content area
    if tool == "SSTI Scanner":
        st.header("Server-Side Template Injection Scanner")
        
        # Input form
        with st.form("ssti_form"):
            url = st.text_input("Target URL", placeholder="https://example.com")
            
            # Advanced options in expander
            with st.expander("Advanced Options"):
                cookies = st.text_area("Cookies (one per line, format: key=value)", 
                                     help="Enter cookies in format: key=value")
                headers = st.text_area("Headers (one per line, format: key=value)",
                                     help="Enter headers in format: key=value")
                
                # Payload selection
                st.subheader("Payload Options")
                selected_payloads = st.multiselect(
                    "Select Payload Types",
                    ["Jinja2", "Twig", "FreeMarker", "Velocity"],
                    default=["Jinja2", "Twig"]
                )
            
            submit = st.form_submit_button("Start Scan")
            
            if submit:
                if not url:
                    st.error("Please enter a target URL")
                    return
                
                # Process cookies and headers
                cookies_dict = {}
                if cookies:
                    for cookie in cookies.split('\n'):
                        if '=' in cookie:
                            key, value = cookie.strip().split('=', 1)
                            cookies_dict[key.strip()] = value.strip()
                
                headers_dict = {}
                if headers:
                    for header in headers.split('\n'):
                        if '=' in header:
                            key, value = header.strip().split('=', 1)
                            headers_dict[key.strip()] = value.strip()
                
                # Show progress
                with st.spinner("Scanning for SSTI vulnerabilities..."):
                    results = run_ssti_scan(url, cookies_dict, headers_dict, selected_payloads)
                    
                    # Display results in a nice box
                    st.markdown('<div class="report-box">', unsafe_allow_html=True)
                    st.text(results)
                    st.markdown('</div>', unsafe_allow_html=True)
    
    elif tool == "SSRF Scanner":
        st.header("Server-Side Request Forgery Scanner")
        st.info("SSRF Scanner functionality coming soon!")
    
    elif tool == "Directory Fuzzer":
        st.header("Directory Fuzzer (FFUF)")
        
        with st.form("ffuf_form"):
            url = st.text_input("Target URL", placeholder="https://example.com")
            
            # Wordlist selection
            wordlist = st.selectbox(
                "Select Wordlist",
                ["common.txt", "directory-list-2.3-medium.txt", "directory-list-2.3-small.txt"]
            )
            
            # File extensions
            extensions = st.text_input("File Extensions (comma-separated)", "php,html,txt")
            
            submit = st.form_submit_button("Start Fuzzing")
            
            if submit:
                if not url:
                    st.error("Please enter a target URL")
                    return
                
                with st.spinner("Fuzzing directories..."):
                    results = run_ffuf_scan(url, wordlist, extensions)
                    
                    # Display results
                    st.markdown('<div class="report-box">', unsafe_allow_html=True)
                    st.text(results)
                    st.markdown('</div>', unsafe_allow_html=True)
    
    elif tool == "OSINT Scanner":
        st.header("OSINT Scanner")
        
        target = st.text_input("Enter target domain (e.g., example.com):")
        
        with st.expander("Advanced Options"):
            shodan_api_key = st.text_input("Shodan API Key (optional):", type="password")
        
        if st.button("Run OSINT Scan"):
            if target:
                with st.spinner("Running OSINT scan..."):
                    results = run_osint_scan(target, shodan_api_key)
                    
                    if results:
                        # Create tabs for different sections
                        tabs = st.tabs([
                            "WHOIS", "DNS", "Subdomains", "Ports", 
                            "Security", "SSL", "Wayback"
                        ])
                        
                        # WHOIS Information
                        with tabs[0]:
                            st.subheader("WHOIS Information")
                            whois_data = results.get('whois', {})
                            if 'error' not in whois_data:
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.markdown("**Domain Information**")
                                    for key in ['registrar', 'creation_date', 'expiration_date', 'status', 'dnssec']:
                                        if whois_data.get(key):
                                            st.text(f"{key}: {whois_data[key]}")
                                
                                with col2:
                                    st.markdown("**Contact Information**")
                                    for key in ['registrant', 'admin', 'tech']:
                                        if whois_data.get(key):
                                            st.text(f"{key}: {whois_data[key]}")
                                
                                st.markdown("**Name Servers**")
                                for ns in whois_data.get('name_servers', []):
                                    st.text(f"- {ns}")
                            else:
                                st.error(f"WHOIS Error: {whois_data['error']}")
                        
                        # DNS Information
                        with tabs[1]:
                            st.subheader("DNS Information")
                            dns_data = results.get('dns', {})
                            for record_type, records in dns_data.items():
                                if isinstance(records, list):
                                    st.markdown(f"**{record_type} Records**")
                                    for record in records:
                                        st.text(f"- {record}")
                                elif isinstance(records, dict):
                                    st.markdown(f"**{record_type}**")
                                    for key, value in records.items():
                                        st.text(f"- {key}: {value}")
                                else:
                                    st.text(f"{record_type}: {records}")
                        
                        # Subdomain Information
                        with tabs[2]:
                            st.subheader("Subdomain Information")
                            subdomain_data = results.get('subdomains', {})
                            if 'error' not in subdomain_data:
                                st.metric("Total Subdomains Found", subdomain_data['total_found'])
                                for subdomain in subdomain_data['subdomains']:
                                    st.text(f"- {subdomain}")
                            else:
                                st.error(f"Subdomain Error: {subdomain_data['error']}")
                        
                        # Port Scan Results
                        with tabs[3]:
                            st.subheader("Port Scan Results")
                            port_data = results.get('port_scan', {})
                            if 'error' not in port_data:
                                if port_data:
                                    for port, info in port_data.items():
                                        st.markdown(f"**Port {port}** ({info['service']})")
                                        st.text(f"Status: {info['status']}")
                                else:
                                    st.info("No open ports found")
                            else:
                                st.error(f"Port Scan Error: {port_data['error']}")
                        
                        # Security Headers
                        with tabs[4]:
                            st.subheader("Security Headers")
                            headers_data = results.get('security_headers', {})
                            if 'error' not in headers_data:
                                for header, info in headers_data.items():
                                    col1, col2 = st.columns([1, 2])
                                    with col1:
                                        st.markdown(f"**{header}**")
                                        st.text(f"Status: {info['status']}")
                                    with col2:
                                        st.text(f"Value: {info['value']}")
                            else:
                                st.error(f"Security Headers Error: {headers_data['error']}")
                        
                        # SSL Information
                        with tabs[5]:
                            st.subheader("SSL Certificate Information")
                            ssl_data = results.get('ssl_info', {})
                            if 'error' not in ssl_data:
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.markdown("**Certificate Status**")
                                    status_color = "green" if ssl_data.get('status') == 'Valid' else "red"
                                    st.markdown(f"Status: <span style='color:{status_color}'>{ssl_data.get('status')}</span>", unsafe_allow_html=True)
                                    st.text(f"Days Remaining: {ssl_data.get('days_remaining')}")
                                
                                with col2:
                                    st.markdown("**Certificate Details**")
                                    for key in ['subject', 'issuer', 'version', 'serialNumber']:
                                        if ssl_data.get(key):
                                            st.text(f"{key}: {ssl_data[key]}")
                                
                                st.markdown("**Validity Period**")
                                st.text(f"Not Before: {ssl_data.get('notBefore')}")
                                st.text(f"Not After: {ssl_data.get('notAfter')}")
                            else:
                                st.error(f"SSL Info Error: {ssl_data['error']}")
                        
                        # Wayback Machine
                        with tabs[6]:
                            st.subheader("Wayback Machine Data")
                            wayback_data = results.get('wayback_machine', {})
                            if 'error' not in wayback_data:
                                col1, col2 = st.columns(2)
                                with col1:
                                    st.metric("Total Snapshots", wayback_data.get('total_snapshots', 0))
                                    st.text(f"First Snapshot: {wayback_data.get('first_snapshot')}")
                                    st.text(f"Last Snapshot: {wayback_data.get('last_snapshot')}")
                                
                                if 'snapshots' in wayback_data:
                                    st.markdown("**Recent Snapshots**")
                                    for snapshot in wayback_data['snapshots']:
                                        st.markdown(f"**{snapshot['timestamp']}**")
                                        st.text(f"URL: {snapshot['original']}")
                                        st.text(f"Type: {snapshot['mimetype']}")
                            else:
                                st.error(f"Wayback Machine Error: {wayback_data['error']}")
                        
                        # Download Report
                        report = OSINTScanner(target, shodan_api_key).generate_report()
                        st.download_button(
                            label="Download Report",
                            data=report,
                            file_name=f"osint_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                            mime="text/plain"
                        )
                    else:
                        st.error("No results found")
            else:
                st.warning("Please enter a target domain")
    
    elif tool == "Google Dorks":
        st.header("Google Dorks Generator")
        
        with st.form("google_dorks_form"):
            target = st.text_input("Target Domain", placeholder="example.com")
            
            # Dork categories
            st.subheader("Dork Categories")
            categories = st.multiselect(
                "Select Categories",
                ["Site Search", "File Types", "Configuration Files", 
                 "Sensitive Information", "Directory Listings", "Error Messages"],
                default=["Site Search", "File Types", "Sensitive Information"]
            )
            
            submit = st.form_submit_button("Generate Dorks")
            
            if submit:
                if not target:
                    st.error("Please enter a target domain")
                    return
                
                with st.spinner("Generating Google dorks..."):
                    all_dorks = generate_google_dorks(target)
                    st.session_state.google_dorks = all_dorks
                    
                    # Display results
                    st.markdown('<div class="report-box">', unsafe_allow_html=True)
                    for category in categories:
                        if category in all_dorks:
                            st.subheader(category)
                            for dork in all_dorks[category]:
                                st.markdown(f'<div class="dork-box">', unsafe_allow_html=True)
                                st.markdown(f'**Dork:** `{dork}`')
                                search_url = f"https://www.google.com/search?q={dork.replace(' ', '+')}"
                                st.markdown(f'<div class="dork-url">[Search on Google]({search_url})</div>', unsafe_allow_html=True)
                                st.markdown('</div>', unsafe_allow_html=True)
                    st.markdown('</div>', unsafe_allow_html=True)
        
        # Download button outside the form
        if st.session_state.google_dorks:
            dorks_text = ""
            for category, dorks in st.session_state.google_dorks.items():
                dorks_text += f"\n{category}:\n"
                for dork in dorks:
                    dorks_text += f"- {dork}\n"
                    dorks_text += f"  URL: https://www.google.com/search?q={dork.replace(' ', '+')}\n"
            
            st.download_button(
                label="Download Dorks",
                data=dorks_text,
                file_name=f"google_dorks_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )
    
    elif tool == "GitHub Dorks":
        st.header("GitHub Dorks Scanner")
        
        with st.form("github_dorks_form"):
            target = st.text_input("Target (Organization/User/Repository)", 
                                 placeholder="organization-name or username")
            
            # Dork categories
            st.subheader("Dork Categories")
            categories = st.multiselect(
                "Select Categories",
                ["Repositories", "Code", "Issues", "Discussions", 
                 "Documentation", "Configuration", "API", "Security"],
                default=["Repositories", "Code", "Issues"]
            )
            
            submit = st.form_submit_button("Start GitHub Dorking")
            
            if submit:
                if not target:
                    st.error("Please enter a target")
                    return
                
                with st.spinner("Running GitHub dorks..."):
                    scanner = OSINTScanner(target)
                    results = scanner.github_dorking()
                    st.session_state.github_dorks = results
                    
                    # Display results
                    st.markdown('<div class="report-box">', unsafe_allow_html=True)
                    if 'error' not in results:
                        for category, dork_results in results.items():
                            if category in categories:
                                st.subheader(category)
                                for dork_result in dork_results:
                                    st.markdown(f'<div class="dork-box">', unsafe_allow_html=True)
                                    st.markdown(f'**Dork:** `{dork_result["dork"]}`')
                                    for result_type, items in dork_result['results'].items():
                                        if items:
                                            st.markdown(f'**{result_type.upper()}:**')
                                            for item in items:
                                                st.markdown(f'- Repository: [{item["repository"]["full_name"]}]({item["repository"]["html_url"]})')
                                                st.markdown(f'  - File: [{item["path"]}]({item["html_url"]})')
                                                if item['repository']['description']:
                                                    st.markdown(f'  - Description: {item["repository"]["description"]}')
                                    st.markdown('</div>', unsafe_allow_html=True)
                    else:
                        st.error(f"Error: {results['error']}")
                    st.markdown('</div>', unsafe_allow_html=True)
        
        # Download button outside the form
        if st.session_state.github_dorks and 'error' not in st.session_state.github_dorks:
            report = f"GitHub Dorking Report for {target}\n"
            report += "=" * 50 + "\n\n"
            
            for category, dork_results in st.session_state.github_dorks.items():
                report += f"{category}:\n"
                for dork_result in dork_results:
                    report += f"\nDork: {dork_result['dork']}\n"
                    for result_type, items in dork_result['results'].items():
                        if items:
                            report += f"\n{result_type.upper()}:\n"
                            for item in items:
                                report += f"- Repository: {item['repository']['full_name']}\n"
                                report += f"  File: {item['path']}\n"
                                report += f"  URL: {item['html_url']}\n"
                                if item['repository']['description']:
                                    report += f"  Description: {item['repository']['description']}\n"
            
            st.download_button(
                label="Download Report",
                data=report,
                file_name=f"github_dorks_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

if __name__ == "__main__":
    main() 