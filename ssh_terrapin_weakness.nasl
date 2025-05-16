#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187315);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/29");

  script_cve_id("CVE-2023-48795");

  script_name(english:"SSH Terrapin Prefix Truncation Weakness (CVE-2023-48795)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH server is vulnerable to a mitm prefix truncation attack.");
  script_set_attribute(attribute:"description", value:
"The remote SSH server is vulnerable to a man-in-the-middle prefix truncation weakness known as Terrapin. This can
allow a remote, man-in-the-middle attacker to bypass integrity checks and downgrade the connection's security.

Note that this plugin only checks for remote SSH servers that support either ChaCha20-Poly1305 or CBC with
Encrypt-then-MAC and do not support the strict key exchange countermeasures. It does not check for vulnerable software
versions.");
  script_set_attribute(attribute:"see_also", value:"https://terrapin-attack.com/");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for an update with the strict key exchange countermeasures or disable the affected algorithms.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-48795");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_supported_algorithms.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);

var supports_chacha20 = FALSE;
var c2s_supports_cbc = FALSE;
var c2s_supports_etm = FALSE;
var s2c_supports_cbc = FALSE;
var s2c_supports_etm = FALSE;
var supports_cbcetm = FALSE;
var supports_strictkex = FALSE;
var vulnerable = FALSE;

var encryption_algorithms_client_to_server = get_kb_list('SSH/' + port + '/encryption_algorithms_client_to_server');
var encryption_algorithms_server_to_client = get_kb_list('SSH/' + port + '/encryption_algorithms_server_to_client');
var mac_algorithms_client_to_server = get_kb_list('SSH/' + port + '/mac_algorithms_client_to_server');
var mac_algorithms_server_to_client = get_kb_list('SSH/' + port + '/mac_algorithms_server_to_client');
var kex_algorithms = get_kb_list('SSH/' + port + '/kex_algorithms');

var chacha20poly1305_algo = "chacha20-poly1305@openssh.com";
var etm_suffix = '-etm@openssh.com';
var cbc_suffix = '-cbc';
var kex_strict_algo = 'kex-strict-s-v00@openssh.com';
var report = '';

foreach var c2s_enc (encryption_algorithms_client_to_server)
{
  if (chacha20poly1305_algo >< c2s_enc)
  {
    report += 'Supports following ChaCha20-Poly1305 Client to Server algorithm : ' + c2s_enc + '\n';
    supports_chacha20 = TRUE;
  }

  if (cbc_suffix >< c2s_enc)
  {
    report += 'Supports following CBC Client to Server algorithm               : ' + c2s_enc + '\n';
    c2s_supports_cbc = TRUE;
  }
}

foreach var c2s_mac (mac_algorithms_client_to_server)
{
  if (etm_suffix >< c2s_mac)
  {
    report += 'Supports following Encrypt-then-MAC Client to Server algorithm  : ' + c2s_mac + '\n';
    c2s_supports_etm = TRUE;
  }
}

foreach var s2c_enc (encryption_algorithms_server_to_client)
{
  if (chacha20poly1305_algo >< s2c_enc)
  {
    report += 'Supports following ChaCha20-Poly1305 Server to Client algorithm : ' + s2c_enc + '\n';
    supports_chacha20 = TRUE;
  }
    
  if (cbc_suffix >< s2c_enc)
  {
    report += 'Supports following CBC Server to Client algorithm               : ' + s2c_enc + '\n';   
    s2c_supports_cbc = TRUE;
  }
}

foreach var s2c_mac (mac_algorithms_server_to_client)
{
  if (etm_suffix >< s2c_mac)
  {
    report += 'Supports following Encrypt-then-MAC Server to Client algorithm  : ' + s2c_mac + '\n';    
    s2c_supports_etm = TRUE;
  }
}

foreach var kex_algo (kex_algorithms)
{
  if (kex_strict_algo >< kex_algo)
    supports_strictkex = TRUE;
}

if ((c2s_supports_cbc && c2s_supports_etm) || (s2c_supports_cbc && s2c_supports_etm))
  supports_cbcetm = TRUE;

if ((supports_chacha20 || supports_cbcetm) && !supports_strictkex)
  vulnerable = TRUE;

if (!vulnerable)
  audit(AUDIT_NOT_DETECT, 'An SSH server affected by Terrapin', port);

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
