#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181873);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/13");

  script_cve_id("CVE-2023-28432", "CVE-2023-28434");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/10");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/05/12");

  script_name(english:"MinIO < RELEASE.2023-03-20T20-16-18Z Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The MinIO instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MinIO installed on the remote host is prior to RELEASE.2023-03-20T20-16-18Z. It is, therefore, affected
by multiple vulnerabilities:

  - When deployed in a cluster/in distributed mode  MinIO returns all environment variables, including 
  'MINIO_SECRET_KEY' and 'MINIO_ROOT_PASSWORD', resulting in information disclosure. (CVE-2023-28432)

  - An attacker can use crafted requests to bypass metadata bucket name checking and put an object into any
  bucket while processing PostPolicyBucket. To carry out this attack, the attacker requires credentials with
  arn:aws:s3:::* permission, as well as enabled Console API access. (CVE-2023-28434)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://blog.min.io/security-advisory-stackedcves/");
  script_set_attribute(attribute:"see_also", value:"https://github.com/minio/minio/security/advisories/GHSA-2pxw-r47w-4p8c");
  script_set_attribute(attribute:"see_also", value:"https://github.com/minio/minio/security/advisories/GHSA-6xvq-wj2x-3h3q");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MinIO version RELEASE.2023-03-20T20-16-18Z or later, or apply the workaround mentioned in the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:minio:minio");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("minio_win_installed.nbin", "minio_installed_linux.nbin", "minio_mac_installed.nbin");
  script_require_keys("installed_sw/MinIO");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var win_local;
if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;
else
  win_local = FALSE;

vcf::minio::initialize();
var app_info = vcf::get_app_info(app:'MinIO', win_local:win_local);

# not checking config / patch
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

var constraints = [
  { 'fixed_version': 'RELEASE.2023-03-20T20-16-18Z' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
