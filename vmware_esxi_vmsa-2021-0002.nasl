##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146827);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/23");

  script_cve_id("CVE-2021-21974");
  script_xref(name:"IAVA", value:"2021-A-0109");
  script_xref(name:"CEA-ID", value:"CEA-2021-0012");

  script_name(english:"ESXi 6.5 / 6.7 / 7.0 RCE (VMSA-2021-0002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is missing a security patch and is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 6.5, 6.7 or 7.0 and is affected by a remote code execution vulnerability. 
OpenSLP as used in ESXi (7.0 before ESXi70U1c-17325551, 6.7 before ESXi670-202102401-SG, 6.5 before
ESXi650-202102101-SG) has a heap-overflow vulnerability. A malicious actor residing within the same network segment as
ESXi who has access to port 427 may be able to trigger the heap-overflow issue in OpenSLP service resulting in remote
code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2021-0002.html");
  # https://github.com/straightblast/My-PoC-Exploits/blob/master/CVE-2021-21974.py
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?090c6180");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21974");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin", "slp_tcp_detect.nasl", "slp_udp_detect.nasl");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

# checking if slp service is enabled from workaround https://kb.vmware.com/s/article/76372
if (!get_kb_item("Services/slp")) exit(0, "The SLP service is not enabled on the target device.");

var fixes = make_array(
  '6.5', '17477841', # ESXi650-202102001, ESXi 6.5 P06
  '6.7', '17499825', # ESXi670-202102001, ESXI 6.7 EP18
  '7.0', '17325551'  # ESXi 7.0 Update 1c
);

var rel = get_kb_item_or_exit('Host/VMware/release');
if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');

var ver = get_kb_item_or_exit('Host/VMware/version');
var port  = get_kb_item_or_exit('Host/VMware/vsphere');

var match = pregmatch(pattern:"^ESXi? ([0-9]+\.[0-9]+).*$", string:ver);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7 / 7.0');
ver = match[1];

if (ver !~ "^(7\.0|6\.(5|7))$") audit(AUDIT_OS_NOT, 'ESXi 6.5 / 6.7 / 7.0');

var fixed_build = int(fixes[ver]);

if (empty_or_null(fixed_build)) audit(AUDIT_VER_FORMAT, ver);

match = pregmatch(pattern:"^VMware ESXi.*build-([0-9]+)$", string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '6.5 / 6.7 / 7.0');

var build = int(match[1]);

if (build >= fixed_build) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver + ' build ' + build);

var report = '\n  ESXi version    : ' + ver +
         '\n  Installed build : ' + build +
         '\n  Fixed build     : ' + fixed_build +
         '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
