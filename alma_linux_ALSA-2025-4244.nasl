#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# AlmaLinux Security Advisory ALSA-2025:4244.
##

include('compat.inc');

if (description)
{
  script_id(234914);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id("CVE-2025-0395");
  script_xref(name:"ALSA", value:"2025:4244");
  script_xref(name:"RHSA", value:"2025:4244");

  script_name(english:"AlmaLinux 9 : glibc (ALSA-2025:4244)");

  script_set_attribute(attribute:"synopsis", value:
"The remote AlmaLinux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote AlmaLinux 9 host has packages installed that are affected by a vulnerability as referenced in the
ALSA-2025:4244 advisory.

    * glibc: buffer overflow in the GNU C Library's assert() (CVE-2025-0395)

Tenable has extracted the preceding description block directly from the AlmaLinux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.almalinux.org/9/ALSA-2025-4244.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:4244");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0395");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(131);

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-benchtests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-gconv-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-agr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-anp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ayc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-bem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-bhb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-bho");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-bi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-brx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-byn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-chr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ckb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-cmn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-crh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-cv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-doi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-fil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-fo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-gez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-gv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-hak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-hif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-hne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-iu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-kl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-kok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-kw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ky");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-li");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ln");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-lzh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mfe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mhr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-miq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mjw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mnw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-mt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-nan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-nds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-nhn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-niu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-pap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-quz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-raj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-shn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-shs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-so");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-tcy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-the");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-tig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-to");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-tpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-tt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-unm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-wa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-wae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-wal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-wo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-yi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-yo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-yue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-yuw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-minimal-langpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss_db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:alma:linux:nss_hesiod");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::baseos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::crb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::highavailability");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::nfv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::realtime");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::resilientstorage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::sap_hana");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:alma:linux:9::supplementary");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Alma Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AlmaLinux/release", "Host/AlmaLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/AlmaLinux/release');
if (isnull(os_release) || 'AlmaLinux' >!< os_release) audit(AUDIT_OS_NOT, 'AlmaLinux');
var os_ver = pregmatch(pattern: "AlmaLinux release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'AlmaLinux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'AlmaLinux 9.x', 'AlmaLinux ' + os_ver);

if (!get_kb_item('Host/AlmaLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'AlmaLinux', cpu);

var pkgs = [
    {'reference':'glibc-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-all-langpacks-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-benchtests-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-common-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-devel-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-doc-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-gconv-extra-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-headers-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-aa-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-af-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-agr-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ak-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-am-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-an-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-anp-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ar-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-as-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ast-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ayc-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-az-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-be-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-bem-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ber-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-bg-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-bhb-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-bho-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-bi-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-bn-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-bo-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-br-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-brx-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-bs-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-byn-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ca-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ce-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-chr-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ckb-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-cmn-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-crh-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-cs-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-csb-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-cv-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-cy-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-da-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-de-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-doi-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-dsb-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-dv-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-dz-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-el-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-en-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-eo-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-es-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-et-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-eu-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-fa-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ff-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-fi-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-fil-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-fo-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-fr-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-fur-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-fy-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ga-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-gd-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-gez-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-gl-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-gu-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-gv-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ha-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-hak-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-he-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-hi-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-hif-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-hne-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-hr-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-hsb-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ht-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-hu-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-hy-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ia-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-id-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ig-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ik-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-is-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-it-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-iu-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ja-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ka-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-kab-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-kk-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-kl-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-km-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-kn-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ko-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-kok-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ks-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ku-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-kw-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ky-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-lb-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-lg-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-li-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-lij-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ln-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-lo-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-lt-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-lv-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-lzh-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mag-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mai-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mfe-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mg-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mhr-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mi-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-miq-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mjw-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mk-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ml-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mn-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mni-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mnw-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mr-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ms-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-mt-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-my-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-nan-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-nb-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-nds-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ne-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-nhn-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-niu-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-nl-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-nn-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-nr-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-nso-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-oc-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-om-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-or-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-os-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-pa-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-pap-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-pl-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ps-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-pt-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-quz-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-raj-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ro-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ru-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-rw-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sa-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sah-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sat-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sc-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sd-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-se-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sgs-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-shn-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-shs-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-si-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sid-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sk-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sl-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sm-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-so-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sq-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sr-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ss-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-st-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sv-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-sw-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-szl-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ta-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-tcy-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-te-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-tg-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-th-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-the-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ti-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-tig-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-tk-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-tl-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-tn-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-to-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-tpi-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-tr-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ts-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-tt-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ug-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-uk-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-unm-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ur-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-uz-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-ve-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-vi-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-wa-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-wae-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-wal-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-wo-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-xh-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-yi-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-yo-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-yue-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-yuw-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-zh-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-langpack-zu-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-locale-source-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-minimal-langpack-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-nss-devel-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-static-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'glibc-utils-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'libnsl-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'nscd-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'nss_db-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
    {'reference':'nss_hesiod-2.34-125.el9_5.8.alma.1', 'release':'9', 'el_string':'el9_5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'Alma-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc / glibc-all-langpacks / glibc-benchtests / glibc-common / etc');
}
