#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164584);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2017-12652",
    "CVE-2017-15715",
    "CVE-2017-18190",
    "CVE-2017-18551",
    "CVE-2018-1283",
    "CVE-2018-1303",
    "CVE-2018-10896",
    "CVE-2018-20836",
    "CVE-2018-20843",
    "CVE-2019-2974",
    "CVE-2019-5094",
    "CVE-2019-5188",
    "CVE-2019-5482",
    "CVE-2019-8675",
    "CVE-2019-8696",
    "CVE-2019-9454",
    "CVE-2019-9458",
    "CVE-2019-10098",
    "CVE-2019-11068",
    "CVE-2019-11719",
    "CVE-2019-11727",
    "CVE-2019-11756",
    "CVE-2019-12450",
    "CVE-2019-12614",
    "CVE-2019-12749",
    "CVE-2019-14822",
    "CVE-2019-14866",
    "CVE-2019-15217",
    "CVE-2019-15807",
    "CVE-2019-15903",
    "CVE-2019-15917",
    "CVE-2019-16231",
    "CVE-2019-16233",
    "CVE-2019-16935",
    "CVE-2019-16994",
    "CVE-2019-17006",
    "CVE-2019-17023",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-17498",
    "CVE-2019-18197",
    "CVE-2019-18282",
    "CVE-2019-18808",
    "CVE-2019-19046",
    "CVE-2019-19055",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19126",
    "CVE-2019-19332",
    "CVE-2019-19447",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19530",
    "CVE-2019-19534",
    "CVE-2019-19537",
    "CVE-2019-19767",
    "CVE-2019-19807",
    "CVE-2019-19956",
    "CVE-2019-20054",
    "CVE-2019-20095",
    "CVE-2019-20386",
    "CVE-2019-20388",
    "CVE-2019-20636",
    "CVE-2019-20811",
    "CVE-2019-20907",
    "CVE-2019-1010305",
    "CVE-2020-1749",
    "CVE-2020-1927",
    "CVE-2020-1934",
    "CVE-2020-1971",
    "CVE-2020-2574",
    "CVE-2020-2732",
    "CVE-2020-2752",
    "CVE-2020-2780",
    "CVE-2020-2812",
    "CVE-2020-6829",
    "CVE-2020-7595",
    "CVE-2020-8177",
    "CVE-2020-8492",
    "CVE-2020-8622",
    "CVE-2020-8623",
    "CVE-2020-8624",
    "CVE-2020-8631",
    "CVE-2020-8632",
    "CVE-2020-8647",
    "CVE-2020-8649",
    "CVE-2020-9383",
    "CVE-2020-10690",
    "CVE-2020-10732",
    "CVE-2020-10742",
    "CVE-2020-10751",
    "CVE-2020-10769",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-12243",
    "CVE-2020-12400",
    "CVE-2020-12401",
    "CVE-2020-12402",
    "CVE-2020-12403",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-13943",
    "CVE-2020-14305",
    "CVE-2020-14314",
    "CVE-2020-14331",
    "CVE-2020-14385",
    "CVE-2020-14422",
    "CVE-2020-14779",
    "CVE-2020-14781",
    "CVE-2020-14782",
    "CVE-2020-14792",
    "CVE-2020-14796",
    "CVE-2020-14797",
    "CVE-2020-14803",
    "CVE-2020-15862",
    "CVE-2020-15999",
    "CVE-2020-17527",
    "CVE-2020-24394",
    "CVE-2020-25212",
    "CVE-2020-25643",
    "CVE-2021-3156"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/27");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.19.1)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.19.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.19.1 advisory.

  - In Network Security Services (NSS) before 3.46, several cryptographic primitives had missing length
    checks. In cases where the application calling the library did not perform a sanity check on the inputs it
    could result in a crash due to a buffer overflow. (CVE-2019-17006)

  - Heap buffer overflow in the TFTP protocol handler in cURL 7.19.4 to 7.65.3. (CVE-2019-5482)

  - In all versions of cpio before 2.13 does not properly validate input files when generating TAR archives.
    When cpio is used to create TAR archives from paths an attacker can write to, the resulting archive may
    contain files with permissions the attacker did not have or in paths he did not have access to. Extracting
    those archives from a high-privilege user without carefully reviewing them may lead to the compromise of
    the system. (CVE-2019-14866)

  - If an HTTP/2 client connecting to Apache Tomcat 10.0.0-M1 to 10.0.0-M7, 9.0.0.M1 to 9.0.37 or 8.5.0 to
    8.5.57 exceeded the agreed maximum number of concurrent streams for a connection (in violation of the
    HTTP/2 protocol), it was possible that a subsequent request made on that connection could contain HTTP
    headers - including HTTP/2 pseudo headers - from a previous request rather than the intended headers. This
    could lead to users seeing responses for unexpected resources. (CVE-2020-13943)

  - In libexpat in Expat before 2.2.7, XML input including XML names that contain a large number of colons
    could make the XML parser consume a high amount of RAM and CPU resources while processing (enough to be
    usable for denial-of-service attacks). (CVE-2018-20843)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.19.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6af7891");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5482");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2020-15862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sudo Heap-Based Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/16");
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
  { 'fixed_version' : '5.19.1', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.19.1 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.19.1', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.19.1 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
