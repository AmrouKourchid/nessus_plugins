#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179166);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/12");

  script_cve_id(
    "CVE-2022-2127",
    "CVE-2023-3347",
    "CVE-2023-34966",
    "CVE-2023-34967",
    "CVE-2023-34968"
  );
  script_xref(name:"IAVA", value:"2023-A-0376-S");

  script_name(english:"Samba 4.16.x < 4.16.10 / 4.17.x < 4.17.9 / 4.18.x < 4.18.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote Samba server is potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Samba running on the remote host is 4.16.x prior to 4.16.10, 4.17.x prior to 4.17.9, or 4.18.x prior to
4.18.4.  It is, therefore, potentially affected by multiple vulnerabilities, including the following:

  - An out-of-bounds read error was found in Samba due to insufficient length checks in winbindd_pam_auth_crap.c. When 
    performing NTLM authentication, the client replies to cryptographic challenges back to the server. These replies 
    have variable lengths, and Winbind fails to check the lan manager response length. When Winbind is used for NTLM 
    authentication, a maliciously crafted request can trigger an out-of-bounds read in Winbind, possibly resulting in 
    a crash. (CVE-2022-2127) 

  - An infinite loop condition was found in Samba's mdssvc RPC service for Spotlight. When parsing Spotlight mdssvc 
    RPC packets sent by the client, the core unmarshalling function sl_unpack_loop() did not validate a field in the 
    network packet that contains the count of elements in an array-like structure. By passing 0 as the count value, 
    the attacked function will run in an endless loop consuming 100% CPU. This flaw allows an attacker to issue a 
    malformed RPC request, triggering an infinite loop, resulting in a denial of service condition. (CVE-2023-34966)

  - A vulnerability was found in Samba's SMB2 packet signing mechanism. The SMB2 packet signing is not enforced if an 
    admin configured 'server signing = required' or for SMB2 connections to Domain Controllers where SMB2 packet 
    signing is mandatory. This flaw allows an attacker to perform attacks, such as a man-in-the-middle attack, by 
    intercepting the network traffic and modifying the SMB2 messages between client and server, affecting the 
    integrity of the data. (CVE-2023-3347)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2022-2127.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-3347.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-34966.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-34967.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/security/CVE-2023-34968.html");
  script_set_attribute(attribute:"see_also", value:"https://www.samba.org/samba/history/security.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Samba version 4.18.5, 4.17.10, 4.16.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:samba:samba");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_nativelanman.nasl");
  script_require_keys("SMB/NativeLanManager", "SMB/samba", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var app = vcf::samba::get_app_info();
vcf::check_granularity(app_info:app, sig_segments:3);

var constraints = [
  {'min_version':'4.16.0',  'fixed_version':'4.16.11'},
  {'min_version':'4.17.0', 'fixed_version':'4.17.10'},
  {'min_version':'4.18.0', 'fixed_version':'4.18.5'}
];

vcf::check_version_and_report(app_info:app, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
