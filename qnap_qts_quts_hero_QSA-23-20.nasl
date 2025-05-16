#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187054);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/20");

  script_cve_id(
    "CVE-2023-3961",
    "CVE-2023-4091",
    "CVE-2023-4154",
    "CVE-2023-42669",
    "CVE-2023-42670"
  );

  script_name(english:"QNAP QTS / QuTS hero Vulnerabilities in Samba (QSA-23-20)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of QNAP QTS / QuTS hero installed on the remote host is affected by multiple vulnerabilities as referenced
in the QSA-23-20 advisory.

  - A path traversal vulnerability was identified in Samba when processing client pipe names connecting to
    Unix domain sockets within a private directory. Samba typically uses this mechanism to connect SMB clients
    to remote procedure call (RPC) services like SAMR LSA or SPOOLSS, which Samba initiates on demand.
    However, due to inadequate sanitization of incoming client pipe names, allowing a client to send a pipe
    name containing Unix directory traversal characters (../). This could result in SMB clients connecting as
    root to Unix domain sockets outside the private directory. If an attacker or client managed to send a pipe
    name resolving to an external service using an existing Unix domain socket, it could potentially lead to
    unauthorized access to the service and consequential adverse events, including compromise or service
    crashes. (CVE-2023-3961)

  - A vulnerability was discovered in Samba, where the flaw allows SMB clients to truncate files, even with
    read-only permissions when the Samba VFS module acl_xattr is configured with acl_xattr:ignore system
    acls = yes. The SMB protocol allows opening files when the client requests read-only access but then
    implicitly truncates the opened file to 0 bytes if the client specifies a separate OVERWRITE create
    disposition request. The issue arises in configurations that bypass kernel file system permissions checks,
    relying solely on Samba's permissions. (CVE-2023-4091)

  - A design flaw was found in Samba's DirSync control implementation, which exposes passwords and secrets in
    Active Directory to privileged users and Read-Only Domain Controllers (RODCs). This flaw allows RODCs and
    users possessing the GET_CHANGES right to access all attributes, including sensitive secrets and
    passwords. Even in a default setup, RODC DC accounts, which should only replicate some passwords, can gain
    access to all domain secrets, including the vital krbtgt, effectively eliminating the RODC / DC
    distinction. Furthermore, the vulnerability fails to account for error conditions (fail open), like out-
    of-memory situations, potentially granting access to secret attributes, even under low-privileged attacker
    influence. (CVE-2023-4154)

  - A vulnerability was found in Samba's rpcecho development server, a non-Windows RPC server used to test
    Samba's DCE/RPC stack elements. This vulnerability stems from an RPC function that can be blocked
    indefinitely. The issue arises because the rpcecho service operates with only one worker in the main RPC
    task, allowing calls to the rpcecho server to be blocked for a specified time, causing service
    disruptions. This disruption is triggered by a sleep() call in the dcesrv_echo_TestSleep() function
    under specific conditions. Authenticated users or attackers can exploit this vulnerability to make calls
    to the rpcecho server, requesting it to block for a specified duration, effectively disrupting most
    services and leading to a complete denial of service on the AD DC. The DoS affects all other services as
    rpcecho runs in the main RPC task. (CVE-2023-42669)

  - A flaw was found in Samba. It is susceptible to a vulnerability where multiple incompatible RPC listeners
    can be initiated, causing disruptions in the AD DC service. When Samba's RPC server experiences a high
    load or unresponsiveness, servers intended for non-AD DC purposes (for example, NT4-emulation classic
    DCs) can erroneously start and compete for the same unix domain sockets. This issue leads to partial
    query responses from the AD DC, causing issues such as The procedure number is out of range when using
    tools like Active Directory Users. This flaw allows an attacker to disrupt AD DC services.
    (CVE-2023-42670)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.qnap.com/en/security-advisory/QSA-23-20");
  script_set_attribute(attribute:"solution", value:
"Apply the solution referenced in the QSA-23-20 advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3961");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:qnap:qts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:qnap:quts_hero");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("qnap_qts_quts_hero_web_detect.nbin", "qnap_qts_installed.nbin", "qnap_quts_hero_installed.nbin");
  script_require_ports("installed_sw/QNAP QTS", "installed_sw/QNAP QuTS hero");

  exit(0);
}

include('vcf.inc');
include('vcf_extras_qnap.inc');

var app_info = vcf::qnap::get_app_info();

var constraints = [
  { 'min_version' : '5.1.0', 'max_version' : '5.1.3', 'product' : 'QTS', 'fixed_display' : 'QTS 5.1.3.2578 build 20231110', 'Number' : '2578', 'Build' : '20231110' },
  { 'min_version' : '5.1.0', 'max_version' : '5.1.3', 'product' : 'QuTS hero', 'fixed_display' : 'QuTS hero h5.1.3.2578 build 20231110', 'Number' : '2578', 'Build' : '20231110' }
];
vcf::qnap::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
