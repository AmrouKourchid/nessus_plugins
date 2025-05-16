#TRUSTED 7a6ae5ceb6305698f147741eaf3f86714fcc01c77ca975650eb41a6a6a2477d46bbbc1493366a446bf7e09e2f865ce3ffc760504b2e50b9779f4e1c1090c6ad90f5d683dd6855b052ebe7686a82be6e90cd33fe056ed30cd2774521b06c06c51b55c56eb3e84095018b1c647d573e475790fb6caa661a93419cc62b2b1d2309f42a70e5d0b9c40041bdbf57b96ecbf74ea08087ae273e3db5a6811577175ea8fae534697bf2f32c951152a83457ee090294385a186d85a84854150716a875273bde8709512962ea260ece4830606ee5df00c6969e751f52d7e80a563b31a03f58a04707b35756d7fed0a3ddca199486ac118a8254113590659cf732f8c8a62d6f9e70617351c9bea9a92d0f68cc59238a2d4946ed52876c04c4e6e0e4984869e6ae0c7e1d5fc0211a53b9ae1c8c2398748a53630954c6aa03eba1f011792c9cb41713b5bceaea87c35bcdd72e9f5e83fab17c521dfaac32451f3f17a843c05851213d22b88753405bbb71a905c3ebc60f71037818de798bb98c0590559f9ee9589c0789cc954190f48444dfec14e674f6cc50d7faafc7c172093a0c9884e36a9cbf8d29ad7e393efe4d3899f153d95e39ddb68dac41a65eef496c26f72c7b6ae717abc229073b66a7d87347b90cf8f76e59a37ab7e865fd564fce7f54d242b43f309b93a43550f3ec4540fca42a4b4944a2fbf10ba81d583bf44bc76b8c47d8d
#TRUST-RSA-SHA256 08e2e0b22687a0e0821dad40a48020ec2648ad42ce6f352bd9798484616f3dafbca306586bead27a92a53e4acd625e80b3c84b468bd2d3357e2cffbe6c96b275f91663e6af260d4ff0fbc115a05d69926c12396ad792d1227249356294eec1ed3dfc0c0aaf83254939a473230928ea0da47cba857cc3256eae0a5ad0faa6037cc6b467ea8551fcd9f862e9ba5d3f72083d73198ac9c39bb784097a8a1f700809ab07b7db57d9cd6cca0e326515c150eb38e908b487b5976fad44b0ad302614a9ef52130f1a512e56dce8e714a36cff1cfa216a35db80e1bcbfeea425418be94a785db9b39957731de13fa9bec0ee5a76bddf0a4a7545ab55d066139b4a82e7102c5e3ff0b209f3bd7331e4bfd185e00049f561b6cd967f41581401727bfa8a50871281453a92236e7d2c31c7314bb4c1eb706c566c32df0f74fcb68d7ed229d63b993635c32beb6658da30eb525bc96806a56e017b3badf835842c78aafdd6bf51f8e13954306c2f839535d427623a343a954a5dfed85e0f600a4d8ed230330e13094d9f74137d9cc9c660b5df042d932a534771753bca4671c4647008c3f6a7f6acda00b664e5a774c708ab924cea1c09061937e98cba94befa5e32d4729f50210f2c309205f601d872ad2fe4dd10151e9ed5306ae747afd07879004ad8f450ac7263304ad612af7e4aa603f8bde899b0709e2fcb1bffd5d7fc34577a4e64cc
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179835);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id("CVE-2023-36840");
  script_xref(name:"JSA", value:"JSA71647");

  script_name(english:"Juniper Junos OS Vulnerability (JSA71647)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a vulnerability as referenced in the JSA71647
advisory.

  - A Reachable Assertion vulnerability in Routing Protocol Daemon (RPD) of Juniper Networks Junos OS and
    Junos OS Evolved allows a locally-based, low-privileged attacker to cause a Denial of Service (DoS).
    (CVE-2023-36840)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://supportportal.juniper.net/s/article/Overview-of-the-Juniper-Networks-SIRT-Quarterly-Security-Bulletin-Publication-Process
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?99086ea4");
  # https://supportportal.juniper.net/s/article/In-which-releases-are-vulnerabilities-fixed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b616ed59");
  # https://supportportal.juniper.net/s/article/Common-Vulnerability-Scoring-System-CVSS-and-Juniper-s-Security-Advisories
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d4fd08b");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA71647");
  # https://supportportal.juniper.net/s/article/2023-07-Security-Bulletin-Junos-OS-and-Junos-OS-Evolved-An-rpd-crash-occurs-when-a-specific-L2VPN-command-is-run-CVE-2023-36840
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bf3e9b8c");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA71647");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36840");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');


var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'0.0', 'fixed_ver':'19.3R3-S7'},
  {'min_ver':'19.4', 'fixed_ver':'19.4R3-S10'},
  {'min_ver':'20.1', 'fixed_ver':'20.1R3-S4'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R3-S6'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R3-S6'},
  {'min_ver':'20.4', 'fixed_ver':'20.4R3-S5'},
  {'min_ver':'20.1', 'fixed_ver':'21.1R3-S4'},
  {'min_ver':'21.1-EVO', 'fixed_ver':'21.1R3-S3-EVO'},
  {'min_ver':'21.2', 'fixed_ver':'21.2R3-S3'},
  {'min_ver':'21.2-EVO', 'fixed_ver':'21.2R3-S5-EVO'},
  {'min_ver':'21.3', 'fixed_ver':'21.3R3-S2'},
  {'min_ver':'21.3-EVO', 'fixed_ver':'21.3R3-S4-EVO'},
  {'min_ver':'21.4', 'fixed_ver':'21.4R3'},
  {'min_ver':'21.4-EVO', 'fixed_ver':'21.4R3-EVO'},
  {'min_ver':'22.1', 'fixed_ver':'22.1R3'},
  {'min_ver':'22.1-EVO', 'fixed_ver':'22.1R3-EVO'},
  {'min_ver':'22.2', 'fixed_ver':'22.2R2'},
  {'min_ver':'22.2-EVO', 'fixed_ver':'22.2R2-EVO'},
  {'min_ver':'22.3', 'fixed_ver':'22.3R2'},
  {'min_ver':'22.3-EVO', 'fixed_ver':'22.3R2-EVO'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);
junos_report(ver:ver, fix:fix, severity:SECURITY_WARNING);
