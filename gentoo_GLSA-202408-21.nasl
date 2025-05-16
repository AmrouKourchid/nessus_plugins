#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202408-21.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(205345);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/30");

  script_cve_id(
    "CVE-2020-22673",
    "CVE-2020-22674",
    "CVE-2020-22675",
    "CVE-2020-22677",
    "CVE-2020-22678",
    "CVE-2020-22679",
    "CVE-2020-25427",
    "CVE-2020-35979",
    "CVE-2020-35980",
    "CVE-2020-35981",
    "CVE-2020-35982",
    "CVE-2021-4043",
    "CVE-2021-21834",
    "CVE-2021-21835",
    "CVE-2021-21836",
    "CVE-2021-21837",
    "CVE-2021-21838",
    "CVE-2021-21839",
    "CVE-2021-21840",
    "CVE-2021-21841",
    "CVE-2021-21842",
    "CVE-2021-21843",
    "CVE-2021-21844",
    "CVE-2021-21845",
    "CVE-2021-21846",
    "CVE-2021-21847",
    "CVE-2021-21848",
    "CVE-2021-21849",
    "CVE-2021-21850",
    "CVE-2021-21851",
    "CVE-2021-21852",
    "CVE-2021-21853",
    "CVE-2021-21854",
    "CVE-2021-21855",
    "CVE-2021-21856",
    "CVE-2021-21857",
    "CVE-2021-21858",
    "CVE-2021-21859",
    "CVE-2021-21860",
    "CVE-2021-21861",
    "CVE-2021-21862",
    "CVE-2021-30014",
    "CVE-2021-30015",
    "CVE-2021-30019",
    "CVE-2021-30020",
    "CVE-2021-30022",
    "CVE-2021-30199",
    "CVE-2021-31254",
    "CVE-2021-31255",
    "CVE-2021-31256",
    "CVE-2021-31257",
    "CVE-2021-31258",
    "CVE-2021-31259",
    "CVE-2021-31260",
    "CVE-2021-31261",
    "CVE-2021-31262",
    "CVE-2021-32132",
    "CVE-2021-32134",
    "CVE-2021-32135",
    "CVE-2021-32136",
    "CVE-2021-32137",
    "CVE-2021-32138",
    "CVE-2021-32139",
    "CVE-2021-32437",
    "CVE-2021-32438",
    "CVE-2021-32439",
    "CVE-2021-32440",
    "CVE-2021-33361",
    "CVE-2021-33362",
    "CVE-2021-33363",
    "CVE-2021-33364",
    "CVE-2021-33365",
    "CVE-2021-33366",
    "CVE-2021-36412",
    "CVE-2021-36414",
    "CVE-2021-36417",
    "CVE-2021-36584",
    "CVE-2021-40559",
    "CVE-2021-40562",
    "CVE-2021-40563",
    "CVE-2021-40564",
    "CVE-2021-40565",
    "CVE-2021-40566",
    "CVE-2021-40567",
    "CVE-2021-40568",
    "CVE-2021-40569",
    "CVE-2021-40570",
    "CVE-2021-40571",
    "CVE-2021-40572",
    "CVE-2021-40573",
    "CVE-2021-40574",
    "CVE-2021-40575",
    "CVE-2021-40576",
    "CVE-2021-40592",
    "CVE-2021-40606",
    "CVE-2021-40607",
    "CVE-2021-40608",
    "CVE-2021-40609",
    "CVE-2021-40942",
    "CVE-2021-40944",
    "CVE-2021-41456",
    "CVE-2021-41457",
    "CVE-2021-41458",
    "CVE-2021-41459",
    "CVE-2021-44918",
    "CVE-2021-44919",
    "CVE-2021-44920",
    "CVE-2021-44921",
    "CVE-2021-44922",
    "CVE-2021-44923",
    "CVE-2021-44924",
    "CVE-2021-44925",
    "CVE-2021-44926",
    "CVE-2021-44927",
    "CVE-2021-45258",
    "CVE-2021-45259",
    "CVE-2021-45260",
    "CVE-2021-45262",
    "CVE-2021-45263",
    "CVE-2021-45266",
    "CVE-2021-45267",
    "CVE-2021-45288",
    "CVE-2021-45289",
    "CVE-2021-45291",
    "CVE-2021-45292",
    "CVE-2021-45297",
    "CVE-2021-45760",
    "CVE-2021-45762",
    "CVE-2021-45763",
    "CVE-2021-45764",
    "CVE-2021-45767",
    "CVE-2021-45831",
    "CVE-2021-46038",
    "CVE-2021-46039",
    "CVE-2021-46040",
    "CVE-2021-46041",
    "CVE-2021-46042",
    "CVE-2021-46043",
    "CVE-2021-46044",
    "CVE-2021-46045",
    "CVE-2021-46046",
    "CVE-2021-46047",
    "CVE-2021-46049",
    "CVE-2021-46051",
    "CVE-2021-46234",
    "CVE-2021-46236",
    "CVE-2021-46237",
    "CVE-2021-46238",
    "CVE-2021-46239",
    "CVE-2021-46240",
    "CVE-2021-46311",
    "CVE-2021-46313",
    "CVE-2022-1035",
    "CVE-2022-1172",
    "CVE-2022-1222",
    "CVE-2022-1441",
    "CVE-2022-1795",
    "CVE-2022-2453",
    "CVE-2022-2454",
    "CVE-2022-2549",
    "CVE-2022-3178",
    "CVE-2022-3222",
    "CVE-2022-3957",
    "CVE-2022-4202",
    "CVE-2022-24249",
    "CVE-2022-24574",
    "CVE-2022-24575",
    "CVE-2022-24576",
    "CVE-2022-24577",
    "CVE-2022-24578",
    "CVE-2022-26967",
    "CVE-2022-27145",
    "CVE-2022-27146",
    "CVE-2022-27147",
    "CVE-2022-27148",
    "CVE-2022-29339",
    "CVE-2022-29340",
    "CVE-2022-29537",
    "CVE-2022-30976",
    "CVE-2022-36186",
    "CVE-2022-36190",
    "CVE-2022-36191",
    "CVE-2022-38530",
    "CVE-2022-43039",
    "CVE-2022-43040",
    "CVE-2022-43042",
    "CVE-2022-43043",
    "CVE-2022-43044",
    "CVE-2022-43045",
    "CVE-2022-43254",
    "CVE-2022-43255",
    "CVE-2022-45202",
    "CVE-2022-45204",
    "CVE-2022-45283",
    "CVE-2022-45343",
    "CVE-2022-46489",
    "CVE-2022-46490",
    "CVE-2022-47086",
    "CVE-2022-47087",
    "CVE-2022-47088",
    "CVE-2022-47089",
    "CVE-2022-47091",
    "CVE-2022-47092",
    "CVE-2022-47093",
    "CVE-2022-47094",
    "CVE-2022-47095",
    "CVE-2022-47653",
    "CVE-2022-47654",
    "CVE-2022-47656",
    "CVE-2022-47657",
    "CVE-2022-47658",
    "CVE-2022-47659",
    "CVE-2022-47660",
    "CVE-2022-47661",
    "CVE-2022-47662",
    "CVE-2022-47663"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/10/21");

  script_name(english:"GLSA-202408-21 : GPAC: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202408-21 (GPAC: Multiple Vulnerabilities)

    Multiple vulnerabilities have been discovered in GPAC. Please review the CVE identifiers referenced below
    for details.

Tenable has extracted the preceding description block directly from the Gentoo Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202408-21");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=785649");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835341");
  script_set_attribute(attribute:"solution", value:
"All GPAC users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=media-video/gpac-2.2.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1795");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-36190");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:gpac");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'media-video/gpac',
    'unaffected' : make_list("ge 2.2.0"),
    'vulnerable' : make_list("lt 2.2.0")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'GPAC');
}
