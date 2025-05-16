#TRUSTED 8bd771039b07c5b3e750c6d6b50d5ab63bbd7ad24f24765a706a1801593c889cd1323ade5bd76143c1c46efc3f96b2fc95ee58a7f3be2417fad7b91f6caf6bb3bbb9312bde8e8f64c0684796960dfb138dc331a9c5be1d49b86bbf90abd4ce4d1e6bf57dc229be32eedcfc4d72879edf268b1114735d2e3184b78b328de33c3fcf7b653427a6c690e23f86f1ed391658ce3e2980e6dd37f3fa4ee027310923efd79018b366470c06693f0fd52374216fc39543a22525ecd9d7dd18ce1542ac54182e5607783694d46382b1588d02dcfe582d8b5015d32e058ae042a68057fe655615a85990c2f3ca29d96323889c2d2da3065bfb90acb4c36bcbd44b3435ccec0640136119c7d7838379af24d1a78b028a348e89e1e8e61a79748062dc51acb5997192f563418caf387d3d3c01dd577786f95d5d197df26bfdb8b9183ba749d9b0c0b4014537adba15d44b8fea422a9fc9caa1c95d0a84f062ce9d0254c791373468aec1d6c8d052376d8aa19c318bce9c5426142854a21dba13096002d3ed9672a2a6e2ed2427d1892748140b02fb41b634959d15a1a2a3b3c472f1795a8a22b656469de7815d1a1352337c43e60ce79dc0802c16f25bac46b7e51c6035bc2747a46148506cde940f901c381677c914b73f45b5b6534999e19b4d057e65d5e04e390b1a543f26d608e03b61cc6ddca5edb9d5686c37b397295632aba008c0d4
#TRUST-RSA-SHA256 b15a31f351d915ba7f8efda00b7f264593730af913a8093bff7d90558d44b0aeef0aed256cb713ad679e1249e3a33a0e4ef6c37b2afe4dd7b646c8e8af3f9cdd87aaf6684bf35ade9f6378ca8762bb4e4dbb308f41f6c1d8479c77fbf54c5ba40abf8bd430a4bdde6d3a615c782268038265b85c298e92266bb1583cbd66b6ae377f0e31ac88c718e2674da17e8642b34849f2c65532ee145ed9f6a4e09c321d654663267523f08a65e7b8f3af427fe72f8de035e12872e7ed6f42c94e0f20eff68efd43a04b7adc05c099e881a82977ef05a623a58c5f2a25b84fb7a21e4ff2f26b2fc3512b720dde501b1c9e1aa0c09b959b02b5b4835bb73cb49343b68349c65884c9a638dcee130819e8b12dc0c2486119fd3fe0f6ec335579d653823d1492b06238f5b47e309dba9cd934a778025a696063f9fd9a5c4c0efce54fb2165759fef8d42135e484d6044a753092a4425e1ef6c8e041f6fbd22bef2a8933f25179ace3da840d2830c39669bf0a266e92a3d8223e0d2acc6a0fb3403210540b4d3f9fed903e4ce154aa6e9856b992cf995cc8772b4a9d70bea661c55c79836e523dba5dbe31cedd7422496ed1635c8fb9a4aad0c21079dbb8c9b6ee76b09577492220ca3048c6e636b287ac70ce7234dfdf34a2d9c0b14985628758b68da23e9ddf449d1228945a9d7eeb4b4f0940fb996d82f3021d9b6b82f7d3c5fe897faf66
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(191756);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id("CVE-2024-20338");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi30539");
  script_xref(name:"CISCO-SA", value:"cisco-sa-secure-privesc-sYxQO6ds");
  script_xref(name:"IAVA", value:"2024-A-0139");

  script_name(english:"Cisco Secure Client for Linux with ISE Posture Module Privilege Escalation (cisco-sa-secure-privesc-sYxQO6ds)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Client for Linux with ISE Posture Module is
affected by a privilege escalation vulnerability.

  - A vulnerability in the ISE Posture (System Scan) module of Cisco Secure Client for Linux could allow an
    authenticated, local attacker to elevate privileges on an affected device. This vulnerability is due to
    the use of an uncontrolled search path element. An attacker could exploit this vulnerability by copying a
    malicious library file to a specific directory in the filesystem and persuading an administrator to
    restart a specific process. A successful exploit could allow the attacker to execute arbitrary code on an
    affected device with root privileges. (CVE-2024-20338)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-secure-privesc-sYxQO6ds
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab5ab6ee");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi30539");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi30539");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20338");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:secure_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_anyconnect_client_nix_installed.nbin", "cisco_ise_detect.nbin");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "Host/Cisco/ISE/version", "Settings/ParanoidReport");

  exit(0);
}

include('vcf.inc');

# Windows and MacOSX are not vulnerable
var os = get_kb_item_or_exit("Host/OS");
if (('windows' >< tolower(os)) || get_kb_item("Host/MacOSX/Version"))
  audit(AUDIT_HOST_NOT, 'affected');
  
# Posture feature needs to be enabled to be vuln which we are not checking.
if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var app_info = vcf::get_app_info(app:'Cisco AnyConnect Secure Mobility Client', win_local:FALSE);

var constraints = [{'fixed_version': '5.1.2.42'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
