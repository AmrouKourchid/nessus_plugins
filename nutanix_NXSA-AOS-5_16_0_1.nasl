#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164593);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2018-7755",
    "CVE-2018-8087",
    "CVE-2018-9363",
    "CVE-2018-9516",
    "CVE-2018-9517",
    "CVE-2018-10853",
    "CVE-2018-12207",
    "CVE-2018-13053",
    "CVE-2018-13093",
    "CVE-2018-13094",
    "CVE-2018-13095",
    "CVE-2018-14625",
    "CVE-2018-14734",
    "CVE-2018-15594",
    "CVE-2018-16658",
    "CVE-2018-16885",
    "CVE-2018-18281",
    "CVE-2018-20856",
    "CVE-2019-0154",
    "CVE-2019-0155",
    "CVE-2019-1125",
    "CVE-2019-3459",
    "CVE-2019-3460",
    "CVE-2019-3846",
    "CVE-2019-3882",
    "CVE-2019-3900",
    "CVE-2019-5489",
    "CVE-2019-5544",
    "CVE-2019-7222",
    "CVE-2019-9500",
    "CVE-2019-9506",
    "CVE-2019-10126",
    "CVE-2019-11135",
    "CVE-2019-11599",
    "CVE-2019-11729",
    "CVE-2019-11745",
    "CVE-2019-11810",
    "CVE-2019-11833",
    "CVE-2019-14821",
    "CVE-2019-14835",
    "CVE-2019-15239",
    "CVE-2019-18397"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.16.0.1)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.16.0.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.16.0.1 advisory.

  - A flaw that allowed an attacker to corrupt memory and possibly escalate privileges was found in the
    mwifiex kernel module while connecting to a malicious wireless network. (CVE-2019-3846)

  - OpenSLP as used in ESXi and the Horizon DaaS appliances has a heap overwrite issue. VMware has evaluated
    the severity of this issue to be in the Critical severity range with a maximum CVSSv3 base score of 9.8.
    (CVE-2019-5544)

  - Empty or malformed p256-ECDH public keys may trigger a segmentation fault due values being improperly
    sanitized before being copied into memory and used. This vulnerability affects Firefox ESR < 60.8, Firefox
    < 68, and Thunderbird < 60.8. (CVE-2019-11729)

  - When encrypting with a block cipher, if a call to NSC_EncryptUpdate was made with data smaller than the
    block size, a small out of bounds write could occur. This could have caused heap corruption and a
    potentially exploitable crash. This vulnerability affects Thunderbird < 68.3, Firefox ESR < 68.3, and
    Firefox < 71. (CVE-2019-11745)

  - An issue was discovered in the Linux kernel before 4.18.7. In block/blk-core.c, there is an
    __blk_drain_queue() use-after-free because a certain error case is mishandled. (CVE-2018-20856)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.16.0.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ec7e0a4");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3846");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5544");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.16.0.1', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.16.0.1 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.16.0.1', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.16.0.1 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
