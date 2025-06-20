#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from VMware Security Advisory PHSA-2023-5.0-0041. The text
# itself is copyright (C) VMware, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204388);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/25");

  script_cve_id(
    "CVE-2018-10892",
    "CVE-2018-15664",
    "CVE-2018-19653",
    "CVE-2018-20699",
    "CVE-2019-13139",
    "CVE-2019-13509",
    "CVE-2019-15752",
    "CVE-2019-16884",
    "CVE-2019-19794",
    "CVE-2019-3826",
    "CVE-2019-5736",
    "CVE-2020-10750",
    "CVE-2020-13250",
    "CVE-2020-13401",
    "CVE-2020-15257",
    "CVE-2020-25864",
    "CVE-2020-27534",
    "CVE-2020-28053",
    "CVE-2020-35380",
    "CVE-2020-36066",
    "CVE-2020-36067",
    "CVE-2020-7219",
    "CVE-2021-20227",
    "CVE-2021-21284",
    "CVE-2021-21285",
    "CVE-2021-21334",
    "CVE-2021-31239",
    "CVE-2021-32760",
    "CVE-2021-37219",
    "CVE-2021-38698",
    "CVE-2021-41103",
    "CVE-2021-42248",
    "CVE-2021-42836",
    "CVE-2022-23471",
    "CVE-2022-23648",
    "CVE-2022-29153",
    "CVE-2022-31030",
    "CVE-2022-35737",
    "CVE-2022-40716",
    "CVE-2022-46908",
    "CVE-2023-25153",
    "CVE-2023-25173",
    "CVE-2023-2816"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Photon OS 5.0: Telegraf PHSA-2023-5.0-0041");

  script_set_attribute(attribute:"synopsis", value:
"The remote PhotonOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"An update of the telegraf package has been released.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/vmware/photon/wiki/Security-Update-5.0-41.md");
  script_set_attribute(attribute:"solution", value:
"Update the affected Linux packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5736");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-37219");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Docker-Credential-Wincred.exe Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:vmware:photonos:telegraf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:photonos:5.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"PhotonOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/PhotonOS/release", "Host/PhotonOS/rpm-list");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item('Host/PhotonOS/release');
if (isnull(_release) || _release !~ "^VMware Photon") audit(AUDIT_OS_NOT, 'PhotonOS');
if (_release !~ "^VMware Photon (?:Linux|OS) 5\.0(\D|$)") audit(AUDIT_OS_NOT, 'PhotonOS 5.0');

if (!get_kb_item('Host/PhotonOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'PhotonOS', cpu);

var flag = 0;

if (rpm_check(release:'PhotonOS-5.0', cpu:'x86_64', reference:'telegraf-1.27.1-1.ph5')) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'telegraf');
}
