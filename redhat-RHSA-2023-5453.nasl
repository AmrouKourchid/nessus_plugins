#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:5453. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182601);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-4527",
    "CVE-2023-4806",
    "CVE-2023-4813",
    "CVE-2023-4911"
  );
  script_xref(name:"RHSA", value:"2023:5453");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/12");

  script_name(english:"RHEL 9 : glibc (RHSA-2023:5453)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for glibc.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:5453 advisory.

    The glibc packages provide the standard C libraries (libc), POSIX thread libraries (libpthread), standard
    math libraries (libm), and the name service cache daemon (nscd) used by multiple programs on the system.
    Without these libraries, the Linux system cannot function correctly.

    Security Fix(es):

    * glibc: buffer overflow in ld.so leading to privilege escalation (CVE-2023-4911)

    * glibc: Stack read overflow in getaddrinfo in no-aaaa mode (CVE-2023-4527)

    * glibc: potential use-after-free in getaddrinfo() (CVE-2023-4806)

    * glibc: potential use-after-free in gaih_inet() (CVE-2023-4813)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_5453.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a8578c91");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2234712");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237782");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2237798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2238352");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:5453");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL glibc package based on the guidance in RHSA-2023:5453.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4911");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Glibc Tunables Privilege Escalation CVE-2023-4911 (aka Looney Tunables)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(121, 122, 416);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-benchtests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-gconv-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-agr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-anp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ayc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bhb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bho");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-brx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-byn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-chr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ckb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-cmn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-crh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-cv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-doi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-gv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-iu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-kw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ky");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-li");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ln");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-lzh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mfe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mhr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-miq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mjw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mnw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-mt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nhn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-niu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-pap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-quz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-raj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-shn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-shs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-so");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tcy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-the");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-to");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-tt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-unm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-wa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-wae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-wal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-wo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-yi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-yo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-yue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-yuw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-minimal-langpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss_hesiod");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['9','9.2'])) audit(AUDIT_OS_NOT, 'Red Hat 9.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/aus/rhel9/9.2/x86_64/appstream/debug',
      'content/aus/rhel9/9.2/x86_64/appstream/os',
      'content/aus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/aus/rhel9/9.2/x86_64/baseos/debug',
      'content/aus/rhel9/9.2/x86_64/baseos/os',
      'content/aus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/appstream/debug',
      'content/e4s/rhel9/9.2/s390x/appstream/os',
      'content/e4s/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/s390x/baseos/debug',
      'content/e4s/rhel9/9.2/s390x/baseos/os',
      'content/e4s/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/appstream/debug',
      'content/e4s/rhel9/9.2/x86_64/appstream/os',
      'content/e4s/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.2/x86_64/baseos/debug',
      'content/e4s/rhel9/9.2/x86_64/baseos/os',
      'content/e4s/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/appstream/debug',
      'content/eus/rhel9/9.2/s390x/appstream/os',
      'content/eus/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/baseos/debug',
      'content/eus/rhel9/9.2/s390x/baseos/os',
      'content/eus/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/s390x/codeready-builder/debug',
      'content/eus/rhel9/9.2/s390x/codeready-builder/os',
      'content/eus/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/appstream/debug',
      'content/eus/rhel9/9.2/x86_64/appstream/os',
      'content/eus/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/baseos/debug',
      'content/eus/rhel9/9.2/x86_64/baseos/os',
      'content/eus/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/os',
      'content/eus/rhel9/9.2/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-all-langpacks-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-benchtests-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-doc-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-gconv-extra-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.34-60.el9_2.7', 'sp':'2', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.34-60.el9_2.7', 'sp':'2', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-aa-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-af-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-agr-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ak-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-am-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-an-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-anp-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ar-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-as-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ast-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ayc-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-az-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-be-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bem-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ber-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bg-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bhb-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bho-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bi-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bn-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bo-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-br-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-brx-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bs-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-byn-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ca-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ce-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-chr-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ckb-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-cmn-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-crh-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-cs-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-csb-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-cv-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-cy-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-da-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-de-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-doi-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-dsb-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-dv-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-dz-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-el-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-en-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-eo-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-es-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-et-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-eu-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fa-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ff-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fi-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fil-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fo-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fr-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fur-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fy-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ga-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gd-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gez-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gl-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gu-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gv-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ha-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hak-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-he-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hi-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hif-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hne-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hr-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hsb-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ht-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hu-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hy-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ia-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-id-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ig-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ik-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-is-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-it-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-iu-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ja-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ka-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kab-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kk-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kl-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-km-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kn-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ko-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kok-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ks-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ku-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kw-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ky-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lb-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lg-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-li-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lij-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ln-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lo-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lt-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lv-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lzh-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mag-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mai-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mfe-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mg-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mhr-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mi-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-miq-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mjw-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mk-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ml-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mn-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mni-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mnw-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mr-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ms-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mt-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-my-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nan-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nb-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nds-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ne-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nhn-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-niu-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nl-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nn-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nr-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nso-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-oc-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-om-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-or-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-os-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-pa-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-pap-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-pl-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ps-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-pt-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-quz-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-raj-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ro-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ru-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-rw-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sa-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sah-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sat-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sc-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sd-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-se-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sgs-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-shn-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-shs-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-si-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sid-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sk-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sl-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sm-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-so-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sq-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sr-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ss-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-st-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sv-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sw-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-szl-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ta-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tcy-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-te-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tg-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-th-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-the-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ti-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tig-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tk-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tl-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tn-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-to-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tpi-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tr-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ts-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tt-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ug-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-uk-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-unm-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ur-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-uz-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ve-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-vi-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-wa-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-wae-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-wal-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-wo-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-xh-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-yi-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-yo-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-yue-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-yuw-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-zh-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-zu-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-locale-source-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-minimal-langpack-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-nss-devel-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnsl-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nss_db-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nss_hesiod-2.34-60.el9_2.7', 'sp':'2', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/s390x/appstream/debug',
      'content/dist/rhel9/9.1/s390x/appstream/os',
      'content/dist/rhel9/9.1/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/baseos/debug',
      'content/dist/rhel9/9.1/s390x/baseos/os',
      'content/dist/rhel9/9.1/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.1/s390x/codeready-builder/os',
      'content/dist/rhel9/9.1/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/appstream/debug',
      'content/dist/rhel9/9.1/x86_64/appstream/os',
      'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/baseos/debug',
      'content/dist/rhel9/9.1/x86_64/baseos/os',
      'content/dist/rhel9/9.1/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/appstream/debug',
      'content/dist/rhel9/9.2/s390x/appstream/os',
      'content/dist/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/baseos/debug',
      'content/dist/rhel9/9.2/s390x/baseos/os',
      'content/dist/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.2/s390x/codeready-builder/os',
      'content/dist/rhel9/9.2/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/appstream/debug',
      'content/dist/rhel9/9.2/x86_64/appstream/os',
      'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/baseos/debug',
      'content/dist/rhel9/9.2/x86_64/baseos/os',
      'content/dist/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/appstream/debug',
      'content/dist/rhel9/9.3/s390x/appstream/os',
      'content/dist/rhel9/9.3/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/baseos/debug',
      'content/dist/rhel9/9.3/s390x/baseos/os',
      'content/dist/rhel9/9.3/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.3/s390x/codeready-builder/os',
      'content/dist/rhel9/9.3/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/appstream/debug',
      'content/dist/rhel9/9.3/x86_64/appstream/os',
      'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/baseos/debug',
      'content/dist/rhel9/9.3/x86_64/baseos/os',
      'content/dist/rhel9/9.3/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/appstream/debug',
      'content/dist/rhel9/9.4/s390x/appstream/os',
      'content/dist/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/baseos/debug',
      'content/dist/rhel9/9.4/s390x/baseos/os',
      'content/dist/rhel9/9.4/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.4/s390x/codeready-builder/os',
      'content/dist/rhel9/9.4/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/appstream/debug',
      'content/dist/rhel9/9.4/x86_64/appstream/os',
      'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/baseos/debug',
      'content/dist/rhel9/9.4/x86_64/baseos/os',
      'content/dist/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/appstream/debug',
      'content/dist/rhel9/9.5/s390x/appstream/os',
      'content/dist/rhel9/9.5/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/baseos/debug',
      'content/dist/rhel9/9.5/s390x/baseos/os',
      'content/dist/rhel9/9.5/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/codeready-builder/debug',
      'content/dist/rhel9/9.5/s390x/codeready-builder/os',
      'content/dist/rhel9/9.5/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/appstream/debug',
      'content/dist/rhel9/9.5/x86_64/appstream/os',
      'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/baseos/debug',
      'content/dist/rhel9/9.5/x86_64/baseos/os',
      'content/dist/rhel9/9.5/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/s390x/appstream/debug',
      'content/dist/rhel9/9/s390x/appstream/os',
      'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9/s390x/baseos/debug',
      'content/dist/rhel9/9/s390x/baseos/os',
      'content/dist/rhel9/9/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9/s390x/codeready-builder/debug',
      'content/dist/rhel9/9/s390x/codeready-builder/os',
      'content/dist/rhel9/9/s390x/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/baseos/debug',
      'content/dist/rhel9/9/x86_64/baseos/os',
      'content/dist/rhel9/9/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9/x86_64/codeready-builder/os',
      'content/dist/rhel9/9/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'glibc-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-all-langpacks-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-benchtests-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-common-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-devel-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-doc-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-gconv-extra-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.34-60.el9_2.7', 'cpu':'s390x', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-headers-2.34-60.el9_2.7', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-aa-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-af-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-agr-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ak-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-am-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-an-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-anp-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ar-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-as-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ast-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ayc-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-az-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-be-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bem-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ber-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bg-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bhb-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bho-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bi-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bn-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bo-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-br-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-brx-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-bs-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-byn-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ca-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ce-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-chr-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ckb-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-cmn-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-crh-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-cs-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-csb-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-cv-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-cy-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-da-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-de-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-doi-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-dsb-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-dv-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-dz-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-el-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-en-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-eo-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-es-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-et-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-eu-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fa-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ff-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fi-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fil-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fo-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fr-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fur-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-fy-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ga-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gd-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gez-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gl-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gu-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-gv-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ha-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hak-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-he-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hi-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hif-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hne-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hr-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hsb-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ht-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hu-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-hy-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ia-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-id-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ig-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ik-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-is-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-it-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-iu-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ja-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ka-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kab-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kk-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kl-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-km-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kn-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ko-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kok-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ks-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ku-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-kw-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ky-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lb-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lg-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-li-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lij-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ln-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lo-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lt-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lv-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-lzh-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mag-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mai-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mfe-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mg-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mhr-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mi-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-miq-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mjw-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mk-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ml-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mn-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mni-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mnw-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mr-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ms-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-mt-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-my-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nan-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nb-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nds-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ne-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nhn-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-niu-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nl-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nn-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nr-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-nso-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-oc-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-om-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-or-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-os-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-pa-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-pap-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-pl-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ps-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-pt-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-quz-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-raj-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ro-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ru-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-rw-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sa-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sah-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sat-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sc-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sd-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-se-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sgs-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-shn-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-shs-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-si-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sid-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sk-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sl-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sm-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-so-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sq-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sr-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ss-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-st-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sv-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-sw-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-szl-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ta-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tcy-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-te-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tg-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-th-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-the-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ti-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tig-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tk-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tl-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tn-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-to-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tpi-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tr-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ts-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-tt-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ug-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-uk-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-unm-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ur-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-uz-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-ve-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-vi-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-wa-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-wae-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-wal-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-wo-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-xh-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-yi-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-yo-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-yue-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-yuw-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-zh-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-langpack-zu-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-locale-source-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-minimal-langpack-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-nss-devel-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-static-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'glibc-utils-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libnsl-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nscd-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nss_db-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'nss_hesiod-2.34-60.el9_2.7', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc / glibc-all-langpacks / glibc-benchtests / glibc-common / etc');
}
