#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-2709. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151677);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/08");

  script_cve_id("CVE-2021-29970", "CVE-2021-29976", "CVE-2021-30547");
  script_xref(name:"IAVA", value:"2021-A-0309-S");
  script_xref(name:"IAVA", value:"2021-A-0293-S");

  script_name(english:"Debian DLA-2709-1 : firefox-esr - LTS security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-2709 advisory.

  - Out of bounds write in ANGLE in Google Chrome prior to 91.0.4472.101 allowed a remote attacker to
    potentially perform out of bounds memory access via a crafted HTML page. (CVE-2021-30547)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/firefox-esr");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/lts/security/2021/dla-2709");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-29970");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-29976");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-30547");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/firefox-esr");
  script_set_attribute(attribute:"solution", value:
"Upgrade the firefox-esr packages.

For Debian 9 stretch, these problems have been fixed in version 78.12.0esr-1~deb9u1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-30547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bn-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ca-valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-en-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-en-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-es-mx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-gu-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hi-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ne-np");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-son");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-trs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firefox-esr-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bn-bd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bn-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ca-valencia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-en-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-en-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-cl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-es-mx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-fy-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ga-ie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-gu-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hi-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-hy-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nb-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ne-np");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-nn-no");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-pt-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-son");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-sv-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-trs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('audit.inc');
include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

release = get_kb_item('Host/Debian/release');
if ( isnull(release) ) audit(AUDIT_OS_NOT, 'Debian');
release = chomp(release);
if (! preg(pattern:"^(9)\.[0-9]+", string:release)) audit(AUDIT_OS_NOT, 'Debian 9.0', 'Debian ' + release);
cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

pkgs = [
    {'release': '9.0', 'prefix': 'firefox-esr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-dev', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ach', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-af', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-all', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-an', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ar', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-as', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ast', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-az', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-be', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bg', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bn', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bn-bd', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bn-in', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-br', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-bs', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ca', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ca-valencia', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-cak', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-cs', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-cy', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-da', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-de', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-dsb', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-el', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-en-ca', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-en-gb', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-en-za', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-eo', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-es-ar', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-es-cl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-es-es', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-es-mx', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-et', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-eu', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-fa', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ff', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-fi', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-fr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-fy-nl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ga-ie', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-gd', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-gl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-gn', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-gu-in', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-he', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hi-in', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hsb', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hu', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-hy-am', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ia', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-id', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-is', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-it', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ja', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ka', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-kab', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-kk', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-km', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-kn', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ko', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-lij', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-lt', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-lv', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-mai', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-mk', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ml', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-mr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ms', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-my', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-nb-no', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ne-np', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-nl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-nn-no', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-oc', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-or', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-pa-in', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-pl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-pt-br', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-pt-pt', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-rm', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ro', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ru', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-si', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sk', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-son', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sq', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-sv-se', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ta', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-te', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-th', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-tl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-tr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-trs', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-uk', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-ur', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-uz', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-vi', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-xh', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-zh-cn', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'firefox-esr-l10n-zh-tw', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-dev', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ach', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-af', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-all', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-an', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ar', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-as', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ast', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-az', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-be', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bg', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bn', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bn-bd', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bn-in', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-br', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-bs', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ca', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ca-valencia', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-cak', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-cs', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-cy', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-da', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-de', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-dsb', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-el', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-en-ca', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-en-gb', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-en-za', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-eo', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-es-ar', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-es-cl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-es-es', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-es-mx', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-et', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-eu', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-fa', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ff', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-fi', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-fr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-fy-nl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ga-ie', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-gd', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-gl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-gn', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-gu-in', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-he', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hi-in', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hsb', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hu', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-hy-am', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ia', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-id', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-is', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-it', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ja', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ka', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-kab', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-kk', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-km', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-kn', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ko', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-lij', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-lt', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-lv', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-mai', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-mk', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ml', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-mr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ms', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-my', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-nb-no', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ne-np', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-nl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-nn-no', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-oc', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-or', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-pa-in', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-pl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-pt-br', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-pt-pt', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-rm', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ro', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ru', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-si', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sk', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-son', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sq', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-sv-se', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ta', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-te', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-th', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-tl', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-tr', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-trs', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-uk', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-ur', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-uz', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-vi', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-xh', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-zh-cn', 'reference': '78.12.0esr-1~deb9u1'},
    {'release': '9.0', 'prefix': 'iceweasel-l10n-zh-tw', 'reference': '78.12.0esr-1~deb9u1'}
];

flag = 0;
foreach package_array ( pkgs ) {
  release = NULL;
  prefix = NULL;
  reference = NULL;
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (release && prefix && reference) {
    if (deb_check(release:release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'firefox-esr / firefox-esr-dev / firefox-esr-l10n-ach / etc');
}
