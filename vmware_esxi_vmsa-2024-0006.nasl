#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191711);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id(
    "CVE-2024-22252",
    "CVE-2024-22253",
    "CVE-2024-22254",
    "CVE-2024-22255"
  );
  script_xref(name:"VMSA", value:"2024-0006");
  script_xref(name:"IAVA", value:"2024-A-0120");

  script_name(english:"VMware ESXi 7.0 / 8.0 Multiple Vulnerabilities (VMSA-2024-0006)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware ESXi installed on the remote host is prior to 7.0 Update 3p, 8.0 prior to 8.0 Update 1d, or 8.0
prior to 8.0 Update 2b. It is, therefore, affected by multiple vulnerabilities as referenced in the VMSA-2024-0006
advisory:

  - VMware ESXi, Workstation, and Fusion contain a use-after-free vulnerability in the XHCI USB controller. (CVE-2024-22252)

  - VMware ESXi, Workstation, and Fusion contain a use-after-free vulnerability in the UHCI USB controller. (CVE-2024-22253)

  - VMware ESXi contains an out-of-bounds write vulnerability. (CVE-2024-22254)

  - VMware ESXi, Workstation, and Fusion contain an information disclosure vulnerability in the UHCI USB controller.
    (CVE-2024-22255)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2024-0006.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware ESXi 7.0 Update 3p, 8.0 Update 1d, or 8.0 Update 2b or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/release", "Host/VMware/vsphere");

  exit(0);
}

var fixes = make_array(
    '7.0.0', 23307199,
    '7.0.1', 23307199,
    '7.0.2', 23307199,
    '7.0.3', 23307199,
    '8.0.0', 23299997,
    '8.0.1', 23299997,
    '8.0.2', 23305545
);

var fixed_display = make_array(
    '7.0.0', '7.0U3 23307199',
    '7.0.1', '7.0U3 23307199',
    '7.0.2', '7.0U3 23307199',
    '7.0.3', '7.0U3 23307199',
    '8.0.0', '8.0U1 23299997',
    '8.0.1', '8.0U1 23299997',
    '8.0.2', '8.0U2 23305545'
);

var rel = get_kb_item_or_exit('Host/VMware/release');
if ('ESXi' >!< rel) audit(AUDIT_OS_NOT, 'ESXi');

var port  = get_kb_item_or_exit('Host/VMware/vsphere');

var match = pregmatch(pattern:"^VMware ESXi?o? ([0-9]+\.[0-9]+\.[0-9]+)", string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '7.0 / 8.0');
var ver = match[1];

if (ver !~ "^(7\.0|8\.0)") audit(AUDIT_OS_NOT, 'ESXi 7.0 / 8.0');

var fixed_build = fixes[ver];

if (empty_or_null(fixed_build)) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver);

match = pregmatch(pattern:"^VMware ESXi?o?.*[Bb]uild[- ]([0-9]+)$", string:rel);
if (isnull(match)) audit(AUDIT_UNKNOWN_BUILD, 'VMware ESXi', '7.0 / 8.0');

var build = int(match[1]);

if (build >= fixed_build) audit(AUDIT_INST_VER_NOT_VULN, 'VMware ESXi', ver + ' build ' + build);

var report = '\n  ESXi version    : ' + rel +
         '\n  Installed build : ' + build +
         '\n  Fixed build     : ' + fixed_display[ver] +
         '\n';

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);