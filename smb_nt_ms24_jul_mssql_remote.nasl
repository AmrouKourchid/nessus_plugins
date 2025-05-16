#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216605);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/24");

  script_cve_id(
    "CVE-2024-20701",
    "CVE-2024-21303",
    "CVE-2024-21308",
    "CVE-2024-21317",
    "CVE-2024-21331",
    "CVE-2024-21332",
    "CVE-2024-21333",
    "CVE-2024-21335",
    "CVE-2024-21373",
    "CVE-2024-21398",
    "CVE-2024-21414",
    "CVE-2024-21415",
    "CVE-2024-21425",
    "CVE-2024-21428",
    "CVE-2024-21449",
    "CVE-2024-28928",
    "CVE-2024-35256",
    "CVE-2024-35271",
    "CVE-2024-35272",
    "CVE-2024-37318",
    "CVE-2024-37319",
    "CVE-2024-37320",
    "CVE-2024-37321",
    "CVE-2024-37322",
    "CVE-2024-37323",
    "CVE-2024-37324",
    "CVE-2024-37326",
    "CVE-2024-37327",
    "CVE-2024-37328",
    "CVE-2024-37329",
    "CVE-2024-37330",
    "CVE-2024-37331",
    "CVE-2024-37332",
    "CVE-2024-37333",
    "CVE-2024-37334",
    "CVE-2024-37336",
    "CVE-2024-38087",
    "CVE-2024-38088"
  );
  script_xref(name:"MSKB", value:"5040942");
  script_xref(name:"MSKB", value:"5040939");
  script_xref(name:"MSKB", value:"5040936");
  script_xref(name:"MSKB", value:"5040986");
  script_xref(name:"MSKB", value:"5040944");
  script_xref(name:"MSKB", value:"5040948");
  script_xref(name:"MSKB", value:"5040940");
  script_xref(name:"MSKB", value:"5040946");
  script_xref(name:"MSFT", value:"MS24-5040942");
  script_xref(name:"MSFT", value:"MS24-5040939");
  script_xref(name:"MSFT", value:"MS24-5040936");
  script_xref(name:"MSFT", value:"MS24-5040986");
  script_xref(name:"MSFT", value:"MS24-5040944");
  script_xref(name:"MSFT", value:"MS24-5040948");
  script_xref(name:"MSFT", value:"MS24-5040940");
  script_xref(name:"MSFT", value:"MS24-5040946");

  script_name(english:"Security Updates for Microsoft SQL Server (July 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2024-20701,
    CVE-2024-21303, CVE-2024-21308, CVE-2024-21317,
    CVE-2024-21331, CVE-2024-21332, CVE-2024-21333,
    CVE-2024-21335, CVE-2024-21373, CVE-2024-21398,
    CVE-2024-21414, CVE-2024-21415, CVE-2024-21425,
    CVE-2024-21428, CVE-2024-21449, CVE-2024-28928,
    CVE-2024-35256, CVE-2024-35271, CVE-2024-35272,
    CVE-2024-37318, CVE-2024-37319, CVE-2024-37320,
    CVE-2024-37321, CVE-2024-37322, CVE-2024-37323,
    CVE-2024-37324, CVE-2024-37326, CVE-2024-37327,
    CVE-2024-37328, CVE-2024-37329, CVE-2024-37330,
    CVE-2024-37331, CVE-2024-37332, CVE-2024-37333,
    CVE-2024-37334, CVE-2024-37336, CVE-2024-38087,
    CVE-2024-38088)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040942");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040939");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040936");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040986");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040944");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040948");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040940");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5040946");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5040942
  -KB5040939
  -KB5040936
  -KB5040986
  -KB5040944
  -KB5040948
  -KB5040940
  -KB5040946");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38088");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(139, 445, 1433, "Services/mssql");

  exit(0);
}

var port = get_service(svc:'mssql', exit_on_fail:TRUE);
var instance = get_kb_item('MSSQL/' + port + '/InstanceName');
var version = get_kb_item_or_exit('MSSQL/' + port + '/Version');

# SQL Server checks are already paranoid, but we also can't check for Linux container SQL Server specifically
if (report_paranoia < 2) audit(AUDIT_PARANOID);

var ver = pregmatch(pattern:"^([0-9.]+)([^0-9]|$)", string:version);
if (!isnull(ver) && !isnull(ver[1])) ver = ver[1];

if (
  (ver_compare(ver:ver, minver:'13.0.6455.2', fix: '13.0.6441.1') < 0) ||
  (ver_compare(ver:ver, minver:'13.0.7000.253', fix: '13.0.7037.1') < 0) ||
  (ver_compare(ver:ver, minver:'14.0.1000.169', fix: '14.0.2056.2') < 0) ||
  (ver_compare(ver:ver, minver:'14.0.3006.16',  fix: '14.0.3471.2') < 0) ||
  (ver_compare(ver:ver, minver:'15.0.2000.5',   fix: '15.0.2116.2') < 0) ||
  (ver_compare(ver:ver, minver:'15.0.4003.23',  fix: '15.0.4382.1') < 0) ||
  (ver_compare(ver:ver, minver:'16.0.1000.6',   fix: '16.0.1121.4') < 0) ||
  (ver_compare(ver:ver, minver:'16.0.4003.1',   fix: '16.0.4131.2') < 0) ||
  (ver_compare(ver:ver, minver:'18.0.0.0',      fix: '18.7.0004.0') < 0) ||
  (ver_compare(ver:ver, minver:'19.3.0.0',      fix: '19.3.0005.0') < 0)
)
{
  var report = '';
  if (!empty_or_null(version))  report += '\n  SQL Server Version   : ' + version;
  if (!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'MSSQL', version);
