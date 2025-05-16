#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202401-12.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(187728);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/09");

  script_cve_id(
    "CVE-2023-41335",
    "CVE-2023-42453",
    "CVE-2023-43796",
    "CVE-2023-45129"
  );

  script_name(english:"GLSA-202401-12 : Synapse: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202401-12 (Synapse: Multiple Vulnerabilities)

  - Synapse is an open-source Matrix homeserver written and maintained by the Matrix.org Foundation. When
    users update their passwords, the new credentials may be briefly held in the server database. While this
    doesn't grant the server any added capabilitiesit already learns the users' passwords as part of the
    authentication processit does disrupt the expectation that passwords won't be stored in the database. As
    a result, these passwords could inadvertently be captured in database backups for a longer duration. These
    temporarily stored passwords are automatically erased after a 48-hour window. This issue has been
    addressed in version 1.93.0. Users are advised to upgrade. There are no known workarounds for this issue.
    (CVE-2023-41335)

  - Synapse is an open-source Matrix homeserver written and maintained by the Matrix.org Foundation. Users
    were able to forge read receipts for any event (if they knew the room ID and event ID). Note that the
    users were not able to view the events, but simply mark it as read. This could be confusing as clients
    will show the event as read by the user, even if they are not in the room. This issue has been patched in
    version 1.93.0. Users are advised to upgrade. There are no known workarounds for this issue.
    (CVE-2023-42453)

  - Synapse is an open-source Matrix homeserver Prior to versions 1.95.1 and 1.96.0rc1, cached device
    information of remote users can be queried from Synapse. This can be used to enumerate the remote users
    known to a homeserver. System administrators are encouraged to upgrade to Synapse 1.95.1 or 1.96.0rc1 to
    receive a patch. As a workaround, the `federation_domain_whitelist` can be used to limit federation
    traffic with a homeserver. (CVE-2023-43796)

  - Synapse is an open-source Matrix homeserver written and maintained by the Matrix.org Foundation. Prior to
    version 1.94.0, a malicious server ACL event can impact performance temporarily or permanently leading to
    a persistent denial of service. Homeservers running on a closed federation (which presumably do not need
    to use server ACLs) are not affected. Server administrators are advised to upgrade to Synapse 1.94.0 or
    later. As a workaround, rooms with malicious server ACL events can be purged and blocked using the admin
    API. (CVE-2023-45129)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202401-12");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=914765");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=916609");
  script_set_attribute(attribute:"solution", value:
"All Synapse users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-im/synapse-1.96.0");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-43796");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:synapse");
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
    'name' : 'net-im/synapse',
    'unaffected' : make_list("ge 1.96.0"),
    'vulnerable' : make_list("lt 1.96.0")
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
    severity   : SECURITY_WARNING,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Synapse');
}
