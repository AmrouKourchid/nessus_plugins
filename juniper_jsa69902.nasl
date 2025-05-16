#TRUSTED 82fe828cecb9a44f8d7662a98a6805fa5d5e64d04f45c14d03c255f09bad24b517f8cde0715a7a30402105c140b8bc4b194e949e7021f3c168b659b3540b5b2df6b33951747ca8a2cbbb62a54d64d7623f50873e554e792ae593e01745afea42a57911e6b736db2c4c0bc79324cb3eb328aa7688ede1de8585e6ffb80899e407907b8e32742e797c21073e94ab4c3284a16b6f577f48529c525e01d6db8406a0f8300767e1e4434fb197bbcc15468e7ecd6218c53187afdd811bd4c495c8eed928d39433a5fa96f52d353cc68b390139782d74a59d13108373a98d23657a4c5b28334a24d243a9c7c0376d11b237a053a2c570f6fda2b22f4e0022993bc164acb297179acde2a4bed4beb9b592f7f378052f673e57aba65a2c13f25480ca863bd514d3987ea38c053ffb4c4ea74949fa528c3f85a1498a0db5ffad45e2f648d3bfb0fc6dd7a6af0b88edf6d2424b6a513460f9fdb7006c04ced2364f930ce1bb005bbe650e7b93e32f0c5a8b125c731cfadd02bf4601c5d7847964bf5a3de15799790291cda99f6604593ea1ac95ad7abe6d4efb3c7ab545048cab4e3510007d66901d9f8004e3d7002356e2a24fa275c19c8ff35cb61e6db125b02053bb30dd40c1867f5844345a41bb97c37d3b371e219be63e4844f899ad6888c7b12424d931c2906f612ad2f50a82568ff514416fb2dc30868413598878a6bf2d434086da
#TRUST-RSA-SHA256 4ae6f8f3df843824938b7495a8ae7ffd2c48fb89e5102fc3461ec830cebaceab1b6cdcad7dedf056ce56222779bf18b0ef2d0fefd87c4f434fa0e4ddf3179d8a2a3d96665c5987b8c7b17b5c07fa7ca80c434fea9c2ac6d042a9a07ec3a4e31e787de6e8336cb5ccfb6c60401e647cc52db83c94312bb4493c33beddf0319a4f06c8ce581983ebe4ebdea4e1db94c4004a9206fccdadde8196b5687419220d27982c923a0d9f6b3fde6d3fea84c1c3c9242f6fff528bddc7a186f76c82fc92d75036a890d33b0b778bb70bb41b4b3eb5b0171163b15fe78c527a8b87f0d71a8d477c31249e7b8ffdd2e3cb3be9d5018a797eae4d7ebe151fee9ad2ea2296fb3d2ef6f56386cf79705c8447f9c237c26f561a5610810eb8c5f0b5dea89fb457ac4396dc199ab34dbe345f2bdbcf7f8393b54651a5727a932ac272d15597a66b521c79fb5e88cb4f95810c5593ac70e034bf77ea996f06434855ecdd9b9e77f9d4f90edc479d04a85adafba4b6483a941e815b464718a9f1abcb878c84382ffe6a02eb24e900052f2e4f73830b451686e078ef7a0f2a3081e181dc52babb21cf0625a67e80411fab96792adc182b961ecbdf72e6d297490e6df239de7714360896266fa29646f809e5dba688a9c9912d94358d9b4b2f214afa9b2c997d43994a298b83be60d7acab921e171e9bf2bdb33c7878d3a4cfd5c1603523f5555bcc762a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166319);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/18");

  script_cve_id("CVE-2022-22220");
  script_xref(name:"JSA", value:"JSA69902");
  script_xref(name:"IAVA", value:"2022-A-0421-S");

  script_name(english:"Juniper Junos OS Time-of-check Time-of-use (TOCTOU) Race Condition DoS (JSA69902)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a DoS vulnerability as referenced in the JSA69902
advisory. A Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Routing Protocol Daemon (rpd) of Juniper
Networks Junos OS, Junos OS Evolved allows a network-based unauthenticated attacker to cause a Denial of Service (DoS).

To be vulnerable to this issue a device needs to be configured with a minimal BGP flow spec configuration like in the
following example:

[protocols bgp group <group-name> family <family> flow]

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  # https://supportportal.juniper.net/s/article/2022-10-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-Due-to-a-race-condition-the-rpd-process-can-crash-upon-receipt-of-a-BGP-update-message-containing-flow-spec-route-CVE-2022-22220
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9e1313eb");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA69902");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'18.4', 'fixed_ver':'18.4R2-S10', 'fixed_display':'18.4R2-S10, 18.4R3-S10'},
  {'min_ver':'19.1', 'fixed_ver':'19.1R3-S7'},
  {'min_ver':'19.2', 'fixed_ver':'19.2R1-S8', 'fixed_display':'19.2R1-S8, 19.2R3-S4'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S3'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S2'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3'},
  {'min_ver':'21.1', 'fixed_ver':'21.1R2'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set protocols bgp group .* family .* flow"))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);



var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"protocols evpn", multiline:TRUE)
  || !preg(string:buf, pattern:"leave-sync-route-oldstyle", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'running a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);