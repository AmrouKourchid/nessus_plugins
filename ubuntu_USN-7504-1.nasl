#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7504-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235613);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/08");

  script_cve_id("CVE-2025-2866");
  script_xref(name:"IAVB", value:"2025-B-0063");
  script_xref(name:"USN", value:"7504-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : LibreOffice vulnerability (USN-7504-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-7504-1 advisory.

    Juraj arinay discovered that LibreOffice incorrectly handled verifying PDF signatures. A remote attacker
    could possibly use this issue to generate PDF files that appear to have a valid signature.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7504-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2866");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fonts-opensymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-lokdocview-0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjuh-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libjurt-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblibreoffice-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblibreofficekitgtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libofficebean-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-avmedia-backend-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-base-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-base-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-calc-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-core-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-dev-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-dev-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-draw-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-gtk4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-en-us");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-help-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-impress-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-kde5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-kf5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-kf6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-en-gb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-en-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-gug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-kmr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-pa-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-pt-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-zh-cn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-zh-tw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-math-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-mysql-connector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-plasma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-qt5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-qt6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-report-builder-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-report-builder-bin-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-script-provider-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-script-provider-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-script-provider-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-sdbc-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-sdbc-hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-sdbc-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-sdbc-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-smoketest-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-colibre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-elementary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-human");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-karasa-jaga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-sifr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-sukapura");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-yaru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-subsequentcheckbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-systray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-uiconfig-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-uiconfig-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-uiconfig-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-uiconfig-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-uiconfig-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-uiconfig-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-uiconfig-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-uiconfig-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-writer-nogui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreofficekit-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreofficekit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libridl-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cppu3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cppu3t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cppuhelpergcc3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-cppuhelpergcc3-3t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-purpenvhelpergcc3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-purpenvhelpergcc3-3t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-sal3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-sal3t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-salhelpergcc3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libuno-salhelpergcc3-3t64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunoil-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libunoloader-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-access2base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-scriptforge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-uno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uno-libs-private");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ure-java");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'fonts-opensymbol', 'pkgver': '2:102.11+LibO6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'gir1.2-lokdocview-0.1', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libjuh-java', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libjurt-java', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'liblibreofficekitgtk', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libofficebean-java', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-avmedia-backend-gstreamer', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-base', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-base-core', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-base-drivers', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-base-nogui', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-calc', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-calc-nogui', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-common', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-core', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-core-nogui', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-dev', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-dev-common', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-draw', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-draw-nogui', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-evolution', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-gnome', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-gtk', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-gtk2', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-gtk3', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-ca', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-common', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-cs', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-da', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-de', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-dz', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-el', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-en-gb', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-en-us', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-es', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-et', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-eu', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-fi', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-fr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-gl', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-hi', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-hu', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-id', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-it', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-ja', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-km', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-ko', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-nl', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-om', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-pl', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-pt', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-pt-br', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-ru', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-sk', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-sl', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-sv', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-tr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-vi', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-zh-cn', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-help-zh-tw', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-impress', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-impress-nogui', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-java-common', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-kde', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-kde4', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-kde5', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-kf5', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-af', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-am', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ar', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-as', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ast', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-be', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-bg', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-bn', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-br', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-bs', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ca', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-cs', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-cy', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-da', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-de', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-dz', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-el', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-en-gb', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-en-za', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-eo', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-es', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-et', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-eu', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-fa', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-fi', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-fr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ga', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-gd', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-gl', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-gu', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-gug', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-he', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-hi', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-hr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-hu', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-id', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-in', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-is', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-it', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ja', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ka', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-kk', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-km', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-kmr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-kn', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ko', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-lt', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-lv', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-mk', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ml', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-mn', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-mr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-nb', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ne', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-nl', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-nn', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-nr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-nso', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-oc', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-om', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-or', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-pa-in', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-pl', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-pt', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-pt-br', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ro', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ru', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-rw', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-si', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-sk', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-sl', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-sr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ss', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-st', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-sv', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-szl', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ta', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-te', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-tg', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-th', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-tn', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-tr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ts', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ug', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-uk', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-uz', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-ve', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-vi', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-xh', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-za', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-zh-cn', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-zh-tw', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-l10n-zu', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-librelogo', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-math', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-math-nogui', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-mysql-connector', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-nlpsolver', 'pkgver': '0.9+LibO6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-officebean', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-ogltrans', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-pdfimport', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-plasma', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-qt5', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-report-builder', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-report-builder-bin', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-report-builder-bin-nogui', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-script-provider-bsh', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-script-provider-js', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-script-provider-python', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-sdbc-firebird', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-sdbc-hsqldb', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-sdbc-mysql', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-sdbc-postgresql', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-smoketest-data', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-breeze', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-colibre', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-elementary', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-galaxy', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-hicontrast', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-human', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-karasa-jaga', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-oxygen', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-sifr', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-style-tango', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-subsequentcheckbase', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-systray', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-wiki-publisher', 'pkgver': '1.2.0+LibO6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-writer', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreoffice-writer-nogui', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreofficekit-data', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libreofficekit-dev', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libridl-java', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libuno-cppu3', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libuno-cppuhelpergcc3-3', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libuno-purpenvhelpergcc3-3', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libuno-sal3', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libuno-salhelpergcc3-3', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libunoil-java', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'libunoloader-java', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'python3-access2base', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'python3-uno', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'uno-libs-private', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '20.04', 'pkgname': 'ure', 'pkgver': '1:6.4.7-0ubuntu0.20.04.15'},
    {'osver': '22.04', 'pkgname': 'fonts-opensymbol', 'pkgver': '2:102.12+LibO7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'gir1.2-lokdocview-0.1', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libjuh-java', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libjurt-java', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'liblibreoffice-java', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'liblibreofficekitgtk', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libofficebean-java', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-avmedia-backend-gstreamer', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-base', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-base-core', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-base-drivers', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-base-nogui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-calc', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-calc-nogui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-common', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-core', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-core-nogui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-dev', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-dev-common', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-dev-gui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-draw', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-draw-nogui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-evolution', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-gnome', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-gtk', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-gtk2', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-gtk3', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-ca', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-common', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-cs', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-da', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-de', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-dz', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-el', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-en-gb', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-en-us', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-es', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-et', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-eu', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-fi', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-fr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-gl', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-hi', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-hu', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-id', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-it', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-ja', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-km', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-ko', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-nl', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-om', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-pl', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-pt', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-pt-br', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-ru', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-sk', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-sl', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-sv', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-tr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-vi', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-zh-cn', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-help-zh-tw', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-impress', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-impress-nogui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-java-common', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-kde', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-kde4', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-kde5', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-kf5', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-af', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-am', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ar', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-as', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ast', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-be', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-bg', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-bn', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-br', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-bs', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ca', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-cs', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-cy', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-da', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-de', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-dz', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-el', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-en-gb', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-en-za', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-eo', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-es', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-et', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-eu', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-fa', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-fi', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-fr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ga', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-gd', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-gl', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-gu', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-gug', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-he', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-hi', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-hr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-hu', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-id', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-in', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-is', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-it', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ja', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ka', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-kk', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-km', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-kmr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-kn', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ko', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-lt', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-lv', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-mk', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ml', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-mn', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-mr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-nb', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ne', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-nl', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-nn', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-nr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-nso', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-oc', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-om', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-or', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-pa-in', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-pl', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-pt', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-pt-br', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ro', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ru', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-rw', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-si', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-sk', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-sl', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-sr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ss', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-st', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-sv', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-szl', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ta', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-te', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-tg', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-th', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-tn', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-tr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ts', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ug', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-uk', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-uz', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-ve', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-vi', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-xh', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-za', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-zh-cn', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-zh-tw', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-l10n-zu', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-librelogo', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-math', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-math-nogui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-mysql-connector', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-nlpsolver', 'pkgver': '0.9+LibO7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-nogui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-officebean', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-ogltrans', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-pdfimport', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-plasma', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-qt5', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-report-builder', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-report-builder-bin', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-report-builder-bin-nogui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-script-provider-bsh', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-script-provider-js', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-script-provider-python', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-sdbc-firebird', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-sdbc-hsqldb', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-sdbc-mysql', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-sdbc-postgresql', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-smoketest-data', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-breeze', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-colibre', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-elementary', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-galaxy', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-hicontrast', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-human', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-karasa-jaga', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-oxygen', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-sifr', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-sukapura', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-tango', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-style-yaru', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-subsequentcheckbase', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-systray', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-wiki-publisher', 'pkgver': '1.2.0+LibO7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-writer', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreoffice-writer-nogui', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreofficekit-data', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libreofficekit-dev', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libridl-java', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libuno-cppu3', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libuno-cppuhelpergcc3-3', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libuno-purpenvhelpergcc3-3', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libuno-sal3', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libuno-salhelpergcc3-3', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libunoil-java', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'libunoloader-java', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'python3-access2base', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'python3-uno', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'uno-libs-private', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'ure', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '22.04', 'pkgname': 'ure-java', 'pkgver': '1:7.3.7-0ubuntu0.22.04.10'},
    {'osver': '24.04', 'pkgname': 'fonts-opensymbol', 'pkgver': '4:102.12+LibO24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'gir1.2-lokdocview-0.1', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libjuh-java', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libjurt-java', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'liblibreoffice-java', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'liblibreofficekitgtk', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libofficebean-java', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-base', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-base-core', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-base-drivers', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-base-nogui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-calc', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-calc-nogui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-common', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-core', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-core-nogui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-dev', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-dev-common', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-dev-gui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-draw', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-draw-nogui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-evolution', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-gnome', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-gtk3', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-gtk4', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-ca', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-common', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-cs', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-da', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-de', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-dz', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-el', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-en-gb', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-en-us', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-es', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-et', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-eu', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-fi', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-fr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-gl', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-hi', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-hu', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-id', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-it', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-ja', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-km', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-ko', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-nl', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-om', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-pl', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-pt', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-pt-br', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-ru', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-sk', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-sl', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-sv', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-tr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-vi', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-zh-cn', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-help-zh-tw', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-impress', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-impress-nogui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-java-common', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-kf5', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-af', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-am', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ar', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-as', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ast', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-be', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-bg', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-bn', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-br', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-bs', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ca', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-cs', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-cy', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-da', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-de', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-dz', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-el', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-en-gb', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-en-za', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-eo', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-es', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-et', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-eu', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-fa', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-fi', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-fr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ga', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-gd', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-gl', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-gu', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-gug', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-he', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-hi', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-hr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-hu', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-hy', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-id', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-in', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-is', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-it', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ja', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ka', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-kk', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-km', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-kmr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-kn', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ko', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-lt', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-lv', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-mk', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ml', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-mn', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-mr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-nb', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ne', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-nl', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-nn', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-nr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-nso', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-oc', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-om', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-or', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-pa-in', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-pl', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-pt', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-pt-br', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ro', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ru', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-rw', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-si', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-sk', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-sl', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-sr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ss', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-st', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-sv', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-szl', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ta', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-te', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-tg', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-th', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-tn', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-tr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ts', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ug', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-uk', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-uz', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-ve', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-vi', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-xh', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-za', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-zh-cn', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-zh-tw', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-l10n-zu', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-librelogo', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-math', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-math-nogui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-nlpsolver', 'pkgver': '4:0.9+LibO24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-nogui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-officebean', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-plasma', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-qt5', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-qt6', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-report-builder', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-report-builder-bin', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-report-builder-bin-nogui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-script-provider-bsh', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-script-provider-js', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-script-provider-python', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-sdbc-firebird', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-sdbc-hsqldb', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-sdbc-mysql', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-sdbc-postgresql', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-smoketest-data', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-style-breeze', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-style-colibre', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-style-elementary', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-style-karasa-jaga', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-style-sifr', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-style-sukapura', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-style-tango', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-style-yaru', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-subsequentcheckbase', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-uiconfig-base', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-uiconfig-calc', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-uiconfig-common', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-uiconfig-draw', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-uiconfig-impress', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-uiconfig-math', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-uiconfig-report-builder', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-uiconfig-writer', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-wiki-publisher', 'pkgver': '4:1.2.0+LibO24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-writer', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreoffice-writer-nogui', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreofficekit-data', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libreofficekit-dev', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libridl-java', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libuno-cppu3t64', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libuno-cppuhelpergcc3-3t64', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libuno-purpenvhelpergcc3-3t64', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libuno-sal3t64', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libuno-salhelpergcc3-3t64', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libunoil-java', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'libunoloader-java', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'python3-access2base', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'python3-scriptforge', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'python3-uno', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'uno-libs-private', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'ure', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.04', 'pkgname': 'ure-java', 'pkgver': '4:24.2.7-0ubuntu0.24.04.4'},
    {'osver': '24.10', 'pkgname': 'fonts-opensymbol', 'pkgver': '4:102.12+LibO24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'gir1.2-lokdocview-0.1', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libjuh-java', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libjurt-java', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'liblibreoffice-java', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'liblibreofficekitgtk', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libofficebean-java', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-base', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-base-core', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-base-drivers', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-base-nogui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-calc', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-calc-nogui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-common', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-core', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-core-nogui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-dev', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-dev-common', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-dev-gui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-draw', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-draw-nogui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-evolution', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-gnome', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-gtk3', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-gtk4', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-ca', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-common', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-cs', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-da', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-de', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-dz', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-el', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-en-gb', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-en-us', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-es', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-et', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-eu', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-fi', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-fr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-gl', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-hi', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-hu', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-id', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-it', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-ja', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-km', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-ko', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-nl', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-om', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-pl', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-pt', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-pt-br', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-ru', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-sk', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-sl', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-sv', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-tr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-vi', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-zh-cn', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-help-zh-tw', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-impress', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-impress-nogui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-java-common', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-kf5', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-kf6', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-af', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-am', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ar', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-as', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ast', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-be', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-bg', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-bn', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-br', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-bs', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ca', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-cs', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-cy', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-da', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-de', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-dz', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-el', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-en-gb', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-en-za', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-eo', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-es', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-et', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-eu', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-fa', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-fi', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-fr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ga', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-gd', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-gl', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-gu', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-gug', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-he', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-hi', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-hr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-hu', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-hy', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-id', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-in', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-is', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-it', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ja', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ka', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-kk', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-km', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-kmr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-kn', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ko', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-lt', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-lv', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-mk', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ml', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-mn', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-mr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-nb', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ne', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-nl', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-nn', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-nr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-nso', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-oc', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-om', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-or', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-pa-in', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-pl', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-pt', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-pt-br', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ro', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ru', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-rw', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-si', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-sk', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-sl', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-sr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ss', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-st', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-sv', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-szl', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ta', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-te', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-tg', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-th', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-tn', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-tr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ts', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ug', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-uk', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-uz', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-ve', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-vi', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-xh', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-za', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-zh-cn', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-zh-tw', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-l10n-zu', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-librelogo', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-math', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-math-nogui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-nlpsolver', 'pkgver': '4:0.9+LibO24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-nogui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-officebean', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-plasma', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-qt5', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-qt6', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-report-builder', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-report-builder-bin', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-report-builder-bin-nogui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-script-provider-bsh', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-script-provider-js', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-script-provider-python', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-sdbc-firebird', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-sdbc-hsqldb', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-sdbc-mysql', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-sdbc-postgresql', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-smoketest-data', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-style-breeze', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-style-colibre', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-style-elementary', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-style-karasa-jaga', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-style-sifr', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-style-sukapura', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-style-tango', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-style-yaru', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-subsequentcheckbase', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-uiconfig-base', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-uiconfig-calc', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-uiconfig-common', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-uiconfig-draw', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-uiconfig-impress', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-uiconfig-math', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-uiconfig-report-builder', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-uiconfig-writer', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-wiki-publisher', 'pkgver': '4:1.2.0+LibO24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-writer', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreoffice-writer-nogui', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreofficekit-data', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libreofficekit-dev', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libridl-java', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libuno-cppu3t64', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libuno-cppuhelpergcc3-3t64', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libuno-purpenvhelpergcc3-3t64', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libuno-sal3t64', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libuno-salhelpergcc3-3t64', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libunoil-java', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'libunoloader-java', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'python3-access2base', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'python3-scriptforge', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'python3-uno', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'uno-libs-private', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'ure', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'},
    {'osver': '24.10', 'pkgname': 'ure-java', 'pkgver': '4:24.8.6-0ubuntu0.24.10.2'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
  if (osver && pkgname && pkgver) {
    if (deb_check(release:osver, prefix:pkgname, reference:pkgver, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fonts-opensymbol / gir1.2-lokdocview-0.1 / libjuh-java / etc');
}
