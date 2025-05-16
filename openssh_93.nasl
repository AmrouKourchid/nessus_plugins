#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(173384);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/11");

  script_cve_id("CVE-2023-28531");
  script_xref(name:"IAVA", value:"2023-A-0152-S");

  script_name(english:"OpenSSH < 9.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The SSH server running on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSH installed on the remote host is prior to 9.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the release-9.3 advisory.

  - ssh-add(1): when adding smartcard keys to ssh-agent(1) with the per-hop destination constraints (ssh-add
    -h ...) added in OpenSSH 8.9, a logic error prevented the constraints from being communicated to the
    agent. This resulted in the keys being added without constraints. The common cases of non-smartcard keys
    and keys without destination constraints are unaffected. (CVE-2023-28531) 

  - ssh(1): Portable OpenSSH provides an implementation of the getrrsetbyname(3) function if the standard
    library does not provide it, for use by the VerifyHostKeyDNS feature. A specifically crafted DNS response
    could cause this function to perform an out-of-bounds read of adjacent stack data, but this condition does
    not appear to be exploitable beyond denial-of- service to the ssh(1) client. The getrrsetbyname(3)
    replacement is only included if the system's standard library lacks this function and portable OpenSSH was
    not compiled with the ldns library (--with-ldns). getrrsetbyname(3) is only invoked if using
    VerifyHostKeyDNS to fetch SSHFP records.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssh.com/txt/release-9.3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSH version 9.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28531");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/24");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openbsd:openssh");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssh_detect.nbin");
  script_require_keys("installed_sw/OpenSSH", "Settings/ParanoidReport");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include('backport.inc');
include('vcf.inc');
include('vcf_extras.inc');

# vmware backported into banner : SSH-2.0-OpenSSH-8.9 ,
# but os id is not available at this time in the scan,
# just do paranoid-only plugin.
if (report_paranoia < 2)
    audit(AUDIT_PARANOID);

var port = get_service(svc:'ssh', default:22, exit_on_fail:TRUE);
var app_info = vcf::openssh::get_app_info(app:'OpenSSH', port:port);

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  {'min_version': '8.9', 'fixed_version': '9.3'}
];

vcf::openssh::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
