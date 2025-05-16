#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192466);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/25");

  script_cve_id(
    "CVE-2022-29901",
    "CVE-2022-28693",
    "CVE-2022-23816",
    "CVE-2022-23825",
    "CVE-2022-26373"
  );
  script_xref(name:"VMSA", value:"2022-0020");
  script_xref(name:"CEA-ID", value:"CEA-2022-0026");

  script_name(english:"VMware ESXi 6.5 / 6.7 / 7.0 Multiple Vulnerabilities (VMSA-2022-0020)");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi host is version 6.5, 6.7 or 7.0 and is affected by multiple vulnerabilities, as follows:

  - Intel microprocessor generations 6 to 8 are affected by a new Spectre variant that is able to bypass their 
    retpoline mitigation in the kernel to leak arbitrary data. An attacker with unprivileged user access can hijack 
    return instructions to achieve arbitrary speculative code execution under certain microarchitecture-dependent 
    conditions. (CVE-2022-29901)

  - Non-transparent sharing of return predictor targets between contexts in some Intel(R) Processors may allow an 
    authorized user to potentially enable information disclosure via local access. (CVE-2022-26373)

  - Aliases in the branch predictor may cause some AMD processors to predict the wrong branch type potentially leading 
    to information disclosure. (CVE-2022-23825)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2022-0020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29901");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/release", "Host/VMware/vsphere");

  exit(0);
}

var fixes = make_array(
  '6.5', '19997716', # ESXi650-202207001
  '6.7', '19997733', # ESXi670-202207001
  '7.0', '20036589'  # ESXi 7.0 Update 3f
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
