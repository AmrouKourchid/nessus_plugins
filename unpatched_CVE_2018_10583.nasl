#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(221357);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2018-10583");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2018-10583");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - An information disclosure vulnerability occurs when LibreOffice 6.0.3 and Apache OpenOffice Writer 4.1.5
    automatically process and initiate an SMB connection embedded in a malicious file, as demonstrated by
    xlink:href=file://192.168.0.2/test.jpg within an office:document-content element in a .odt XML document.
    (CVE-2018-10583)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10583");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "libofficebean-java",
     "libreoffice",
     "libreoffice-base",
     "libreoffice-base-core",
     "libreoffice-base-drivers",
     "libreoffice-base-nogui",
     "libreoffice-calc",
     "libreoffice-calc-nogui",
     "libreoffice-common",
     "libreoffice-core",
     "libreoffice-core-nogui",
     "libreoffice-draw",
     "libreoffice-draw-nogui",
     "libreoffice-gnome",
     "libreoffice-help-common",
     "libreoffice-impress",
     "libreoffice-impress-nogui",
     "libreoffice-java-common",
     "libreoffice-l10n-af",
     "libreoffice-l10n-am",
     "libreoffice-l10n-ar",
     "libreoffice-l10n-as",
     "libreoffice-l10n-in",
     "libreoffice-l10n-za",
     "libreoffice-math",
     "libreoffice-math-nogui",
     "libreoffice-nogui",
     "libreoffice-script-provider-bsh",
     "libreoffice-script-provider-js",
     "libreoffice-script-provider-python",
     "libreoffice-sdbc-hsqldb",
     "libreoffice-sdbc-mysql",
     "libreoffice-style-breeze",
     "libreoffice-style-colibre",
     "libreoffice-style-elementary",
     "libreoffice-style-karasa-jaga",
     "libreoffice-style-sifr",
     "libreoffice-style-sukapura",
     "libreoffice-writer",
     "libreoffice-writer-nogui",
     "python3-access2base",
     "python3-uno"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "12"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "libofficebean-java",
     "libreoffice",
     "libreoffice-base",
     "libreoffice-base-core",
     "libreoffice-base-drivers",
     "libreoffice-base-nogui",
     "libreoffice-calc",
     "libreoffice-calc-nogui",
     "libreoffice-common",
     "libreoffice-core",
     "libreoffice-core-nogui",
     "libreoffice-draw",
     "libreoffice-draw-nogui",
     "libreoffice-gnome",
     "libreoffice-help-common",
     "libreoffice-impress",
     "libreoffice-impress-nogui",
     "libreoffice-java-common",
     "libreoffice-l10n-af",
     "libreoffice-l10n-am",
     "libreoffice-l10n-in",
     "libreoffice-l10n-za",
     "libreoffice-math",
     "libreoffice-math-nogui",
     "libreoffice-nogui",
     "libreoffice-officebean",
     "libreoffice-script-provider-bsh",
     "libreoffice-script-provider-js",
     "libreoffice-script-provider-python",
     "libreoffice-sdbc-hsqldb",
     "libreoffice-sdbc-mysql",
     "libreoffice-style-breeze",
     "libreoffice-style-colibre",
     "libreoffice-style-elementary",
     "libreoffice-style-karasa-jaga",
     "libreoffice-style-sifr",
     "libreoffice-style-sukapura",
     "libreoffice-writer",
     "libreoffice-writer-nogui",
     "libunoil-java",
     "python3-access2base",
     "python3-uno"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": [
     "libofficebean-java",
     "libreoffice",
     "libreoffice-base",
     "libreoffice-base-core",
     "libreoffice-base-drivers",
     "libreoffice-base-nogui",
     "libreoffice-calc",
     "libreoffice-calc-nogui",
     "libreoffice-common",
     "libreoffice-core",
     "libreoffice-core-nogui",
     "libreoffice-draw",
     "libreoffice-draw-nogui",
     "libreoffice-gnome",
     "libreoffice-help-common",
     "libreoffice-impress",
     "libreoffice-impress-nogui",
     "libreoffice-java-common",
     "libreoffice-l10n-in",
     "libreoffice-l10n-za",
     "libreoffice-math",
     "libreoffice-math-nogui",
     "libreoffice-nogui",
     "libreoffice-script-provider-bsh",
     "libreoffice-script-provider-js",
     "libreoffice-script-provider-python",
     "libreoffice-sdbc-hsqldb",
     "libreoffice-sdbc-mysql",
     "libreoffice-style-breeze",
     "libreoffice-style-colibre",
     "libreoffice-style-elementary",
     "libreoffice-style-karasa-jaga",
     "libreoffice-style-sifr",
     "libreoffice-style-sukapura",
     "libreoffice-uiconfig-base",
     "libreoffice-uiconfig-common",
     "libreoffice-writer",
     "libreoffice-writer-nogui",
     "python3-access2base",
     "python3-scriptforge",
     "python3-uno"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "13"
       }
      }
     ]
    }
   ]
  },
  {
   "product": {
    "name": "libreoffice",
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "6"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
