#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-4102. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(233595);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/01");

  script_cve_id(
    "CVE-2024-26596",
    "CVE-2024-40945",
    "CVE-2024-42069",
    "CVE-2024-42122",
    "CVE-2024-45001",
    "CVE-2024-47726",
    "CVE-2024-49989",
    "CVE-2024-50061",
    "CVE-2024-54458",
    "CVE-2024-56549",
    "CVE-2024-57834",
    "CVE-2024-57973",
    "CVE-2024-57978",
    "CVE-2024-57979",
    "CVE-2024-57980",
    "CVE-2024-57981",
    "CVE-2024-57986",
    "CVE-2024-57993",
    "CVE-2024-57996",
    "CVE-2024-57997",
    "CVE-2024-57998",
    "CVE-2024-58001",
    "CVE-2024-58007",
    "CVE-2024-58009",
    "CVE-2024-58010",
    "CVE-2024-58011",
    "CVE-2024-58013",
    "CVE-2024-58014",
    "CVE-2024-58016",
    "CVE-2024-58017",
    "CVE-2024-58020",
    "CVE-2024-58034",
    "CVE-2024-58051",
    "CVE-2024-58052",
    "CVE-2024-58054",
    "CVE-2024-58055",
    "CVE-2024-58056",
    "CVE-2024-58058",
    "CVE-2024-58061",
    "CVE-2024-58063",
    "CVE-2024-58068",
    "CVE-2024-58069",
    "CVE-2024-58071",
    "CVE-2024-58072",
    "CVE-2024-58076",
    "CVE-2024-58077",
    "CVE-2024-58080",
    "CVE-2024-58083",
    "CVE-2024-58085",
    "CVE-2024-58086",
    "CVE-2025-21684",
    "CVE-2025-21700",
    "CVE-2025-21701",
    "CVE-2025-21703",
    "CVE-2025-21704",
    "CVE-2025-21705",
    "CVE-2025-21706",
    "CVE-2025-21707",
    "CVE-2025-21708",
    "CVE-2025-21711",
    "CVE-2025-21715",
    "CVE-2025-21716",
    "CVE-2025-21718",
    "CVE-2025-21719",
    "CVE-2025-21722",
    "CVE-2025-21724",
    "CVE-2025-21725",
    "CVE-2025-21726",
    "CVE-2025-21727",
    "CVE-2025-21728",
    "CVE-2025-21731",
    "CVE-2025-21734",
    "CVE-2025-21735",
    "CVE-2025-21736",
    "CVE-2025-21738",
    "CVE-2025-21744",
    "CVE-2025-21745",
    "CVE-2025-21748",
    "CVE-2025-21749",
    "CVE-2025-21750",
    "CVE-2025-21753",
    "CVE-2025-21758",
    "CVE-2025-21760",
    "CVE-2025-21761",
    "CVE-2025-21762",
    "CVE-2025-21763",
    "CVE-2025-21764",
    "CVE-2025-21765",
    "CVE-2025-21766",
    "CVE-2025-21767",
    "CVE-2025-21772",
    "CVE-2025-21775",
    "CVE-2025-21776",
    "CVE-2025-21779",
    "CVE-2025-21780",
    "CVE-2025-21781",
    "CVE-2025-21782",
    "CVE-2025-21785",
    "CVE-2025-21787",
    "CVE-2025-21790",
    "CVE-2025-21791",
    "CVE-2025-21792",
    "CVE-2025-21794",
    "CVE-2025-21795",
    "CVE-2025-21796",
    "CVE-2025-21799",
    "CVE-2025-21802",
    "CVE-2025-21804",
    "CVE-2025-21806",
    "CVE-2025-21811",
    "CVE-2025-21812",
    "CVE-2025-21814",
    "CVE-2025-21819",
    "CVE-2025-21820",
    "CVE-2025-21821",
    "CVE-2025-21823",
    "CVE-2025-21826",
    "CVE-2025-21829",
    "CVE-2025-21830",
    "CVE-2025-21832",
    "CVE-2025-21835"
  );

  script_name(english:"Debian dla-4102 : linux-config-6.1 - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-4102 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-4102-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                        Ben Hutchings
    March 31, 2025                                https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : linux-6.1
    Version        : 6.1.129-1~deb11u1
    CVE ID         : CVE-2024-26596 CVE-2024-40945 CVE-2024-42069 CVE-2024-42122
                     CVE-2024-45001 CVE-2024-47726 CVE-2024-49989 CVE-2024-50061
                     CVE-2024-54458 CVE-2024-56549 CVE-2024-57834 CVE-2024-57973
                     CVE-2024-57978 CVE-2024-57979 CVE-2024-57980 CVE-2024-57981
                     CVE-2024-57986 CVE-2024-57993 CVE-2024-57996 CVE-2024-57997
                     CVE-2024-57998 CVE-2024-58001 CVE-2024-58007 CVE-2024-58009
                     CVE-2024-58010 CVE-2024-58011 CVE-2024-58013 CVE-2024-58014
                     CVE-2024-58016 CVE-2024-58017 CVE-2024-58020 CVE-2024-58034
                     CVE-2024-58051 CVE-2024-58052 CVE-2024-58054 CVE-2024-58055
                     CVE-2024-58056 CVE-2024-58058 CVE-2024-58061 CVE-2024-58063
                     CVE-2024-58068 CVE-2024-58069 CVE-2024-58071 CVE-2024-58072
                     CVE-2024-58076 CVE-2024-58077 CVE-2024-58080 CVE-2024-58083
                     CVE-2024-58085 CVE-2024-58086 CVE-2025-21684 CVE-2025-21700
                     CVE-2025-21701 CVE-2025-21703 CVE-2025-21704 CVE-2025-21705
                     CVE-2025-21706 CVE-2025-21707 CVE-2025-21708 CVE-2025-21711
                     CVE-2025-21715 CVE-2025-21716 CVE-2025-21718 CVE-2025-21719
                     CVE-2025-21722 CVE-2025-21724 CVE-2025-21725 CVE-2025-21726
                     CVE-2025-21727 CVE-2025-21728 CVE-2025-21731 CVE-2025-21734
                     CVE-2025-21735 CVE-2025-21736 CVE-2025-21738 CVE-2025-21744
                     CVE-2025-21745 CVE-2025-21748 CVE-2025-21749 CVE-2025-21750
                     CVE-2025-21753 CVE-2025-21758 CVE-2025-21760 CVE-2025-21761
                     CVE-2025-21762 CVE-2025-21763 CVE-2025-21764 CVE-2025-21765
                     CVE-2025-21766 CVE-2025-21767 CVE-2025-21772 CVE-2025-21775
                     CVE-2025-21776 CVE-2025-21779 CVE-2025-21780 CVE-2025-21781
                     CVE-2025-21782 CVE-2025-21785 CVE-2025-21787 CVE-2025-21790
                     CVE-2025-21791 CVE-2025-21792 CVE-2025-21794 CVE-2025-21795
                     CVE-2025-21796 CVE-2025-21799 CVE-2025-21802 CVE-2025-21804
                     CVE-2025-21806 CVE-2025-21811 CVE-2025-21812 CVE-2025-21814
                     CVE-2025-21819 CVE-2025-21820 CVE-2025-21821 CVE-2025-21823
                     CVE-2025-21826 CVE-2025-21829 CVE-2025-21830 CVE-2025-21832
                     CVE-2025-21835
    Debian Bug     : 1071562 1087807 1088159 1091517 1091858 1093371 1095435
                     1095745 1095764 1098250 1098354 1099138

    Several vulnerabilities have been discovered in the Linux kernel that
    may lead to a privilege escalation, denial of service or information
    leaks.

    For Debian 11 bullseye, these problems have been fixed in version
    6.1.129-1~deb11u1.  This additionally includes many more bug fixes
    from stable update 6.1.129, and a fix for a regression affecting some
    Rockchip SoCs.

    We recommend that you upgrade your linux-6.1 packages.

    For the detailed security status of linux-6.1 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/linux-6.1

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/linux-6.1");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-26596");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-40945");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42069");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-42122");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-45001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-47726");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-49989");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-54458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-56549");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57834");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57973");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57978");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57979");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57980");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57981");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57986");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57993");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57996");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57997");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-57998");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58001");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58007");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58009");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58010");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58011");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58013");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58014");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58016");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58017");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58020");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58034");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58051");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58052");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58054");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58055");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58056");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58058");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58061");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58063");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58068");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58069");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58071");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58072");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58076");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58077");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58080");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58083");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58085");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-58086");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21684");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21700");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21701");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21703");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21704");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21705");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21706");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21707");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21708");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21711");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21715");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21716");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21718");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21719");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21722");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21724");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21725");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21726");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21727");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21728");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21731");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21734");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21735");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21736");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21738");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21744");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21745");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21748");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21749");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21750");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21753");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21758");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21760");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21761");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21762");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21763");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21764");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21765");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21766");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21767");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21775");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21779");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21780");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21781");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21782");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21785");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21787");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21790");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21791");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21792");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21794");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21795");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21796");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21799");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21802");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21804");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21806");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21811");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21812");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21814");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21819");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21820");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21821");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21823");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21826");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21829");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21830");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21832");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2025-21835");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/linux-6.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade the linux-config-6.1 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21791");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-config-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-doc-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.25-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.28-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.31-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-cloud-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-cloud-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-common-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-rt-686-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-rt-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-rt-arm64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-headers-6.1.0-0.deb11.32-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-amd64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-arm64-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-i386-signed-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.25-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.26-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.28-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.31-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-686-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-armmp-lpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-armmp-lpae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-cloud-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-cloud-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-rt-686-pae-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-rt-amd64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-rt-arm64-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-rt-armmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-image-6.1.0-0.deb11.32-rt-armmp-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-kbuild-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-source-6.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-0.deb11.25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-0.deb11.26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-0.deb11.28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-0.deb11.31");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:linux-support-6.1.0-0.deb11.32");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'linux-config-6.1', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-doc-6.1', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-686', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-cloud-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-cloud-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-common', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-common-rt', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-rt-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-rt-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-rt-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.25-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-686', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-cloud-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-cloud-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-common', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-common-rt', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-rt-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-rt-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-rt-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.26-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-686', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-cloud-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-cloud-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-common', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-common-rt', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-rt-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-rt-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-rt-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.28-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-686', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-cloud-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-cloud-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-common', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-common-rt', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-rt-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-rt-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-rt-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.31-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-686', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-cloud-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-cloud-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-common', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-common-rt', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-rt-686-pae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-rt-amd64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-rt-arm64', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-headers-6.1.0-0.deb11.32-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-686-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-amd64-signed-template', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-arm64-signed-template', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-armmp-lpae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-cloud-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-cloud-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-i386-signed-template', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1-rt-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-686-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-armmp-lpae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-cloud-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-cloud-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.25-rt-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-686-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-armmp-lpae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-cloud-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-cloud-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.26-rt-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-686-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-armmp-lpae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-cloud-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-cloud-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.28-rt-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-686-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-armmp-lpae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-cloud-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-cloud-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.31-rt-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-686-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-armmp-lpae', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-armmp-lpae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-cloud-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-cloud-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-rt-686-pae-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-rt-amd64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-rt-arm64-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-rt-armmp', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-image-6.1.0-0.deb11.32-rt-armmp-dbg', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-kbuild-6.1', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-source-6.1', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-support-6.1.0-0.deb11.25', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-support-6.1.0-0.deb11.26', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-support-6.1.0-0.deb11.28', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-support-6.1.0-0.deb11.31', 'reference': '6.1.129-1~deb11u1'},
    {'release': '11.0', 'prefix': 'linux-support-6.1.0-0.deb11.32', 'reference': '6.1.129-1~deb11u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
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
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'linux-config-6.1 / linux-doc-6.1 / linux-headers-6.1-armmp / etc');
}
