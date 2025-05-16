#TRUSTED 98e8925c8c09ad4dd9e947865b1b8a0d019834090e080aafe2cecde0bfc62a202b1234d85d0f699627948ec3e4655ea092d3321987567bdc060665f45858df6cdd3d8048bbc5f90948f15b5206a141983159483f2ad78bce8a0981efebb5377ff756951d6051bfba8a61f76dc1c170ca87ece56589e3e636ec9a2b8ec367c72a19c3fb1a01d457e17fc3c59e6b49896a72ca4be99dd906b0f28c603670c5b35592845e7ba3c365ff04244193d3395545f699eb300f30c6561002a34c79fc2e70e64e9fff3d8137fd7b3f92fc66b35f174c6ec588bda2804d3deea08bf023963184a523f413ea2084ad91600ffb4c0cc0174fc19f2dd4672e2e3aa8447836eda018eccf4c0109f72579e3688a15eac13ac9907de63833e4fd137f8bc5a2993eef4af760843c55d4e04f2816fd32def60b6757e66b5a00975ea6e7265089cc9f05e5135e349f24bbe782a2f562806e8e99aa0d959c5ff9037bb4319d99c9cc154288e11dbd5f132d5807b01a1acc6ed34ac96dfc13ea81b23e61efe026233832a4c6a37f6117c9598fa4efa24eea24517dee75d82061f289ed1ab2619f994efaf0d9f004fadaa47d1584e0b404ed8c070929aa9fce0828efb49aa153079b9dfda8c93632a3e81a06d9e0e3a8084ae034858a4e55896c0b9d70b552ebc58d4d40316084c8dc8f1b441f6203beb77415ddb1d747d7cc3e8cc649bceae010f7ccccb1
#TRUST-RSA-SHA256 8a8caa6b6ed1064831af6c4cf8051887e37e2c6ee8aa082e90927591e91ce534c138081a13b6c61b9539a799ea77180c7c96c95e551c9a4549cd6feffcfc5e74918547880fa3055d0c87bd368c17c4e72ed395673582f6476b6ffb13fb90a86b38c1fd2658031b2c6fa11dcb697bfd83cd9d42b232702581809103d211bd1b865277fc0503233ffe93e5260429fed5608613545ed933d21f66881643f445b14b361231b790763b35288549e63e7ecdf17a21e357049d685d4ee4be4b628379b27cf86e6eda45a61d203d8158bf23415be4e6ab2d6829068c78afd350c2ff02084a6a22acd6a43eb3ba6b9b825c14147277603fb2cc5ed146cbdf4b9351bed394c46c7baad283ba414e789ee79611d36d4355e22208cff219e4f37699a8d2269ebf77677908223ec38512619dbb801e9f6f4146664e1b9ae6a194745aac9bb9b0e147466f30e2f12f708ee24a23dda4a17699b4a37603d952a537d0ee6252d3dc8f36b7ad63562d9f30f58481199c223c10bf990e2b62eb3f1ee8dda23d9c455be6c50ca83a479cc9aeac7dee6c818f4d17a4f57e39c164916a4a0b516dbb50e8ab3f5f0d0283276160ec7a33fbfb55d9270ee0bed59517dae1035c2cd96faa8e4de4473b244c3a0d6d71453d4dcc42ebb886ff9c73d1c5314f2c310cc2629149a31c36bd29d1f408341db4b38e8ad52a43b6660cd711ec7da84998b4dd6eb22c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200215);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/07");

  script_cve_id("CVE-2024-30392");
  script_xref(name:"JSA", value:"JSA79092");
  script_xref(name:"IAVA", value:"2024-A-0232");

  script_name(english:"Juniper Junos OS Vulnerability (JSA79092)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA79092
advisory.

  - A Stack-based Buffer Overflow vulnerability in Flow Processing Daemon (flowd) of Juniper Networks Junos OS
    allows an unauthenticated, network-based attacker to cause Denial of Service (DoS). On all Junos OS MX
    Series platforms with SPC3 and MS-MPC/-MIC, when URL filtering is enabled and a specific URL request is
    received and processed, flowd will crash and restart. Continuous reception of the specific URL request
    will lead to a sustained Denial of Service (DoS) condition. This issue affects: Junos OS: * all versions
    before 21.2R3-S6, * from 21.3 before 21.3R3-S5, * from 21.4 before 21.4R3-S5, * from 22.1 before
    22.1R3-S3, * from 22.2 before 22.2R3-S1, * from 22.3 before 22.3R2-S2, 22.3R3, * from 22.4 before
    22.4R2-S1, 22.4R3. (CVE-2024-30392)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/2024-04-Security-Bulletin-Junos-OS-MX-Series-with-SPC3-and-MS-MPC-MIC-When-URL-filtering-is-enabled-and-a-specific-URL-request-is-received-a-flowd-crash-occurs-CVE-2024-30392
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e99e451e");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA79092");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-30392");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(MS|MX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'21.2R3-S6', 'model':'^(MS|MX)'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S5', 'model':'^(MS|MX)'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3-S5', 'model':'^(MS|MX)'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3-S3', 'model':'^(MS|MX)'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R3-S1', 'model':'^(MS|MX)'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2-S2', 'model':'^(MS|MX)', 'fixed_display':'22.3R2-S2, 22.3R3'},
  {'min_ver':'22.4', 'fixed_ver':'22.4R2-S1', 'model':'^(MS|MX)', 'fixed_display':'22.4R2-S1, 22.4R3'}
];

var override = TRUE;
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  if (!preg(string:buf, pattern:"^set jservices-urlf enable", multiline:TRUE) ||
      !preg(string:buf, pattern:"^set url-filter-template template {client-interfaces.*server-interfaces.*dns-server.*url-filter-database.*}", multiline:TRUE))
    audit(AUDIT_HOST_NOT, 'using a vulnerable configuration');
}

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
