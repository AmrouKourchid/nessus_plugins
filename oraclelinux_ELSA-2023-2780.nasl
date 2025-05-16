#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2023-2780.
##

include('compat.inc');

if (description)
{
  script_id(176297);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-27664",
    "CVE-2022-41715",
    "CVE-2022-41717"
  );
  script_xref(name:"IAVB", value:"2022-B-0042-S");
  script_xref(name:"IAVB", value:"2022-B-0059-S");

  script_name(english:"Oracle Linux 8 : Image / Builder (ELSA-2023-2780)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2023-2780 advisory.

    cockpit-composer
    [45-1.0.1]
    - Make per page documentation links point to Oracle Linux [Orabug: 32013095]

    [45-1]
    - New upstream release

    [44-1]
    - New upstream release

    [43-1]
    - New upstream release

    [42-1]
    - New upstream release

    [40-1]
    - New upstream release

    [39-1]
    - New upstream release

    [38-1]
    - New upstream release

    [37-1]
    - New upstream release

    [35-1]
    - New upstream release

    [34-1]
    - New upstream release

    [33-1]
    - Add support for OCI upload target
    - Update translations
    - Update dependencies

    [32-1]
    - Add Edge Raw, RHEL Installer, Edge Simplified Installer image types
    - Improve user account modal responsiveness
    - Update tests
    - Update minor NPM dependencies
    - Update translation files

    [31-1]
    - Add new ostree image types
    - Improve loading state when waiting for api responses
    - Improve notification system
    - Improve test stability
    - Update NPM dependencies
    - Update translations

    [29-1]
    - Add ability to upload to VMWare
    - Add support for additional ostree parameters
    - Update NPM dependencies
    - Add and update translations
    - Minor test fixes

    [28-1]
    - Use sentence case rather than title case
    - Add and update tests
    - Update translations from weblate
    - Update minor NPM dependencies

    [27-1]
    - Sync with upstream release 27
    - Add additional form validation for the Create Image Wizard
    - Improve page size dropdown styling
    - Improve error state messages
    - Update pagination component for pf4
    - Add wildcards and support for multiple values to input filter
    - Update translations

    [22.1-1]
    - Patternfly imports are standardized to be consistent with cockpit
    - Cancel image build button bug fixed
    - Empty components state provides a help message
    - Wizard component has bug fixes and is refactored for future scalability
    - Test updates
    - ESLint upgraded to version 7 and the code style is improved
    - Translation files are updated from fedora weblate
    - Cockpit-composer's dependency on osbuild-composer  is more specific
    - Coverity scan is now supported to help improve code quality
    - Resolves: #1820539

    [21.1-1]
    - Support setting parameters (ref and parent) for ostree images
    - Loosen restrictions on password strength
    - Various UI refinements

    [20.1-1]
    - Migrate to the osbuild-composer backend
    - Supports uploading images to AWS and Azure

    [12.1-1]
    - Fix integration tests, external test repository URL ceased to exist
    - Translation updates rhbz#1784453
    - Add documentation URL page help menu

    [11-1]
    - Show depsolve errors on the blueprints page
    - Add labels for additional output types (rhbz#1769154)
    - Expose Image Builder on /composer, not /welder
    - Define a URL for each tab on a blueprint page
    - Provide a link in the image creation notification to the Images tab on the blueprint page

    [5-1]
    - Fix PropTypes for the homepage
    - Code clean up for the list of components

    [4-1]
    - Add additional blueprint name validation rhbz#1696415
    - Fix images not loading on refresh
    - Add notification for source repo deletion
    - Fix AppStream ID
    - Translation updates

    [2-1]
    - Strip newlines from SSH keys before saving
    - Translation updates rhbz#1689979

    [1-1]
    - New version 1
    - Translation updates rhbz#1689979

    [0.4-1]
    - New version 0.4
    - Include ability to start lorax-composer rhbz#1708387

    [0.3-1]
    - New version 0.3
    - Add/edit/remove sources
    - Remove new line in encrypted password rhbz#1655862
    - Resolve issues with changes saved to the workspace

    [0.2.1-1]
    - New version 0.2.1
    - Several fixes to User Account creation dialog

    [0.2.0-1]
    - New version 0.2.0
    - Include ability to add a user to a blueprint rhbz#1655862

    [0.1.8-1]
    - New version 0.1.8
    - Provide visual indication when a blueprint component is a dependency
    - Enable Undo to retrieve changes after the Discard Changes action
    - Update how blueprint contents are depsolved when contents are added/removed
    - Display an error if a component is added that results in a depsolve failure
    - Show all versions available for a package
    - Provide ability to specify a wildcard version for a package rhbz#1673066

    [0.1.7-1]
    - New version 0.1.7
      Resolves: rhbz#1640184
    - Capitalize OpenStack corrently in the image create dialog (anilsson)
    - Add AppStream metainfo (mpitt)
    - Make cockpit-composer the only package name (mpitt)
    - Lots of integration test improvements (henrywangxf)

    [0.1.6-1]
    - New version 0.1.6
      Resolves: rhbz#1640184
    - Include spec into release tarball (mpitt)
    - Fix a bug in importSanity test. (henrywangxf)
    - Add RHEL-X in welder-web test scenarios. (henrywangxf)
    - test: Support Cockpit test scenario (mpitt)
    - Makefile: Simplify variable defaults (mpitt)
    - A big commit to fix random failure on chrome. (henrywangxf)
    - Remove inert 'Architecture' field in 'Create Image' dialog (#388) (stefw)
    - po: Update from Fedora Zanata (lars)
    - Remove ForEach to run two test cases but use two separate cases. If there's
      one case failed, I can find it according to case name. (henrywangxf)
    - Wait for delete menu action visable before click it. (henrywangxf)
    - test: Drop node installation from vm.install (mpitt)
    - Don't clean bots/ directory for VM preparation (mpitt)
    - Two improvements: (henrywangxf)
    - Go to view blueprint page by clicking blueprint name link instead of by URL.
      That helps improving case stability. (henrywangxf)
    - Move sed to test/vm.install from test/run because developers do not normally
      use test/run to trigger tests. (henrywangxf)
    - test: Only install node if it isn't already available (mpitt)
    - Makefile: bots is not a phony target (mpitt)

    [0.1.5-1]
    - New version 0.1.5
      Related: rhbz#1613058
    - Found a code coverage bug and fix it. (henrywangxf)
    - Update README.md to support Cockpit CI. (henrywangxf)
    - Updates Create Image modal to not have a default image type (jgiardin)
    - Add support for Modules during Add/Remove (jgiardin)
    - new test: Build mock images and verify download becomes enabled (atodorov)
    - Fix flaky issue when running test on chrome (henrywangxf)
    - Add selenium debug support. (henrywangxf)
    - Creates user-friendly labels to display for image types (jgiardin)
    - Compile with code coverage enabled, collect coverage result and upload to codecov.io. (henrywangxf)
    - new test: verify stock blueprints from backend are displayed (atodorov)
    - Simplify selenium startup again (mpitt)
    - Temporarily support selenium images with and without -debug variants (mpitt)
    - Fix python string format issue (henrywangxf)
    - Remove ugly blank except in tests (henrywangxf)
    - README: We're running tests on Cockpit's CI now (lars)
    - Fix tests to not exit with non-zero code (#362) (henrywangxf)
    - Update Discard Changes to delete workspace (jgiardin)
    - Fix test case 'Then selected component icon should have border' (henrywangxf)
    - Cockpit CI Integration (henrywangxf)
    - Display modules in list of selected components (jgiardin)
    - pass blueprint data that's expected on save (jgiardin)
    - Fix /run/weldr permission issue (henrywangxf)
    - Fix end-to-end test cases (henrywangxf)
    - po: Update Japanese translations from Zanata (lars)

    [0.1.4-1]
    - New version 0.1.4
      Related: rhbz#1613058
    - Adds queue status to an infotip in the Create Image modal (jgiardin)
    - Update Create Image modal to also commit unsaved changes (jgiardin)
    - Catching a couple of minor issues (jgiardin)
    - Update Create Image modal to include blueprint object instead of just name (jgiardin)
    - Update Create Image button selector in end-to-end test (jgiardin)
    - Display warning messages to the user in Create Image modal (jgiardin)
    - use updated property key from api for date created (jgiardin)
    - translations: Fail when zanata-js is not installed (lars)
    - README.md: Add missing translations: (lars)
    - translations: remove test target (lars)
    - po: Update from Fedora Zanata (lars)
    - translations: move po files and scripts to po/ (lars)
    - translations: Strip country code when loading react-intl's locale-data (mpitt)
    - remove redundant .then(data => data) (jgiardin)
    - Add ability to stop builds that are waiting or running (jgiardin)
    - Change text from 'Delete Build' to 'Delete Image' (jgiardin)
    - Update Delete Blueprint modal to match layout of Delete Build (jgiardin)
    - Fix miscellaneous propType warnings (jgiardin)
    - Include confirmation modal for deleting a finished build (jgiardin)
    - Swap order of date and type in the Image list item details (jgiardin)
    - Add Delete action for Finished composes (jgiardin)
    - Add ability to delete Failed builds (jgiardin)
    - test_blueprints: Make blueprint selection more robust (lars)
    - Use upstream patternfly-react's Tab component (lars)
    - Changes en-dash to dash and adds spaces (jgiardin)
    - Updates based on a11y review, also simplified i18n format (jgiardin)
    - minor tweaks to improve the screen reader experience (jgiardin)
    - Makes strings translatable in pagination for available components (jgiardin)
    - Update React and enzyme (lars)
    - package.json: Use ~ instead of ^ versions for dependencies (lars)
    - Drop unused dependencies (lars)
    - package.json: update dependencies (lars)
    - Remove package-lock.json (lars)

    [0.1.3-1]
    - New version 0.1.3
      Related: rhbz#1613058
    - Update Create Image notifications (#328) (jgiardin)
    - Make strings translatable in Pending Changes dialog (#341) (jgiardin)
    - Makefile: don't run po-pull on dist (lars)
    - Add the .spec files to .PHONY (bcl)

    [0.1.2-1]
    - New Version 0.1.2
      Related: rhbz#1613058
    - Add the .spec files to .PHONY (bcl)
    - Add welder-web and cockpit-composer release instructions (bcl)
    - Add a 'tag' target to the Makefile (bcl)
    - Adjust image list layout to improve alignment (jgiardin)
    - Fix blueprint packages getting added to history (jacobdkozol)
    - Fixed bug where startComposeApi would not return start compose response (sfondell)
    - Run make po-push from travis on pushes to master. (dshea)
    - Add a po-push target to the Makefile. (dshea)
    - Don't call compose API on the blueprints page (lars)
    - Support downloading images (lars)
    - Fix fetchComposes() call (lars)
    - Update text string (jgiardin)
    - add bootstrap class for large modals (jgiardin)
    - Fix issues with translated strings and add one more for 'Close' (jgiardin)
    - Make strings translatable (but includes build error) (jgiardin)
    - Update layout (jgiardin)
    - Don't show custom sources section if empty (jgiardin)
    - Add modal for listing sources (jgiardin)
    - Revert 'Revert 'Add python and gcc to the Dockerfiles.'' (dshea)
    - Include translations in the dist tarball (dshea)
    - Remove the zanata-js crud from package-lock.json (dshea)
    - Fix how fetching blueprints/composes is triggered (jacobdkozol)
    - Update API calls error messages (jacobdkozol)
    - Fix polling issue. Add error action. (jacobdkozol)
    - Add loading images from prior sessions and sort by start time. (jacobdkozol)
    - Revert 'Run npm rebuild after npm install.' (lars)
    - Revert 'Add python and gcc to the Dockerfiles.' (lars)
    - Don't update translations on every build (lars)
    - Fix yamllint errors on .travis.yml (dshea)
    - Add new requirements to the travis environment (dshea)
    - Add a script for testing translations. (dshea)
    - Run npm rebuild after npm install. (dshea)
    - Make the editBlueprint selector more specific. (dshea)
    - Add python and gcc to the Dockerfiles. (dshea)
    - Add a i18n section to the README (dshea)
    - Create cockpit translation modules. (dshea)
    - Extract cockpit manifest strings for translation. (dshea)
    - Add translated messages. (dshea)
    - Add scripts for interacting with Zanata. (dshea)
    - Internationalize strings with react-intl. (dshea)
    - Fix PR#309 imported issue. The rpm package should be welder-web*.noarch.rpm, not welder-web*.x86_64.rpm
    (henrywangxf)
    - Build srpm together with rpm (atodorov)
    - Images list UI refinements (jgiardin)
    - cockpituous-release: Use upstream release-source (martinpitt)
    - core: Use escalated privileges to access Lorax API (stefw)
    - remove utils from Layout (jgiardin)
    - Remove unused Layout components (jgiardin)
    - Submit coverage report only if present (atodorov)
    - Use default composer dir without --group option (atodorov)
    - Fix created image not being added to state (jacobdkozol)
    - package.json: Remove bootstrap-select (lars)
    - package.json: Update stylelint (lars)
    - blueprints: Show actual error message (lars)
    - core: propagate errors from cockpitFetch() (lars)

    [0.1.1-1]
    - fixes blueprints end-to-end test (jgiardin)
    - Hides Comment feature from Pending Changes modal (jgiardin)
    - Remove non-functional UI elements/components (jgiardin)
    - fixes line length in unit test (jgiardin)
    - update selector for Edit Blueprint button in test (jgiardin)
    - fixes empty state on blueprints page and tests (jgiardin)
    - fixes spacing errors (jgiardin)
    - fixes bad merges during rebase (jgiardin)
    - handles error case for fetching blueprints (jgiardin)
    - sets timeout on Loading state (jgiardin)
    - how did that 'n' get in there? (jgiardin)
    - fixes line length (jgiardin)
    - Disables actions (jgiardin)
    - Updates UI based on state, for loading and error (jgiardin)
    - Adds reducer for updating state when an error occurs (jgiardin)
    - updates state to hold values for fetch status (jgiardin)
    - components: Use consistent syntax for handlers (lars)
    - Fix two issues. (henrywangxf)
    - test/create.image: simplify shallow wrapper creation (lars)
    - CreateImage: don't call unset handlers (lars)
    - test/create.image: also conider handleStartCompose (lars)
    - correcting the initial state (jgiardin)
    - updates mockState in unit tests to match state updates for Filters (jgiardin)
    - Merge pull request #250 from larskarlitski/remove-mock-data (jgiardin)
    - Remove mock data (lars)
    - Add lorax-composer test and remove stand alone welder-web test. (henrywangxf)
    - Domain socket support in UI testing. (henrywangxf)
    - Update queue status text, Remove cancel button (jacobdkozol)
    - Added status icons for imageListView (jacobdkozol)
    - Add start compose functionality (jacobdkozol)
    - Fix blueprint page issue loading components (jacobdkozol)
    - Remove redux persist (jacobdkozol)
    - Remove unused code (lars)
    - Merge pull request #248 from jgiardino/filter (jgiardin)
    - Merge pull request #262 from andreasn/form-control-fx-style (jgiardin)
    - Fix style of pagination input under available components (anilsson)
    - fix issue when multiple filters are defined (jgiardin)
    - implements filtering and refactors toolbars (jgiardin)

    osbuild
    [81-1]
    - New upstream release

    [80-1]
    - New upstream release

    [79-1]
    - New upstream release

    [78-1]
    - New upstream release

    [77-1]
    - New upstream release

    [76-1]
    - New upstream release

    [75-1]
    - New upstream release

    [73-1]
    - New upstream release

    [72-1]
    - New upstream release

    [71-1]
    - New upstream release

    [70-1]
    - New upstream release

    osbuild-composer
    [75-1]
    - New upstream release

    [74-1]
    - New upstream release

    [73-1]
    - New upstream release

    [72-1]
    - New upstream release

    [71-1]
    - New upstream release

    [70-1]
    - New upstream release

    [69-1]
    - New upstream release

    [68-1]
    - New upstream release

    [67-1]
    - New upstream release

    [62-1]
    - New upstream release

    [60-1]
    - New upstream release

    [59-1]
    - New upstream release

    [58-1]
    - New upstream release

    [57-1]
    - New upstream release

    [55-1]
    - New upstream release

    [54-1]
    - New upstream release

    [53-1]
    - New upstream release

    [51-1]
    - New upstream release

    [46-1]
    - New upstream release

    [45-1]
    - New upstream release

    [44-1]
    - New upstream release

    [43-1]
    - New upstream release

    [42-1]
    - New upstream release

    [40-1]
    - New upstream release

    [37-1]
    - New upstream release

    [36-1]
    - New upstream release

    [33-1]
    - New upstream release

    [32-2]
    - New upstream release

    [31-1]
    - New upstream release

    [28-1]
    - New upstream release

    [27-1]
    - New upstream release

    [26-1]
    - New upstream release

    [25-1]
    - New upstream release 25 (rhbz#1883481)

    [20.1-1]
    - New upstream release 20.1 (rhbz#1872370)

    [20-1]
    - New upstream release 20 (rhbz#1871184 and rhbz#1871179)

    [19-1]
    - New upstream release 19 (rhbz#1866015 and rhbz#1866013)

    [17-1]
    - New upstream release 17 (rhbz#1831653)
    - Obsolete lorax-composer in favor of osbuild-composer (rhbz#1836844)

    [16-1]
    - New upstream release 16 (rhbz#1831653)

    [15-1]
    - New upstream release 15 (rhbz#1831653)

    [14-1]
    - New upstream release 14 (rhbz#1831653)

    [13-1]
    - New upstream release 13 (rhbz#1831653)

    [11-1]
    - Initial package (renamed from golang-github-osbuild-composer) (rhbz#1771887)

    weldr-client
    [35.9-2]
    - tests: Remove default repos before running tests
      Related: rhbz#2168666

    [35.9-1]
    - Copy rhel-88.json test repository from osbuild-composer
    - Update osbuild-composer test repositories from osbuild-composer
    - New release: 35.9 (bcl)
      Resolves: rhbz#2168666
    - tests: Replace os.MkdirTemp with t.TempDir (bcl)
    - blueprint save: Allow overriding bad blueprint names (bcl)
    - tests: Clean up checking err in tests (bcl)
    - composer-cli: Implement blueprints diff (bcl)
    - saveBlueprint: Return the filename to the caller (bcl)
    - composer-cli: Add tests for using --commit with old servers (bcl)
    - weldr: Return error about the blueprints change route (bcl)
    - weldr: Save the http status code as part of APIResponse (bcl)
    - Add --commit support to blueprints save (bcl)
    - Add --commit to blueprints show (bcl)
    - gitleaks: Exclude the test password used in tests (bcl)
    - ci: add tags to AWS instances (tlavocat)
    - Update github.com/BurntSushi/toml to 1.2.1
    - Update github.com/stretchr/testify to 1.8.1
    - Update bump github.com/spf13/cobra to 1.6.1
    - New release: 35.8 (bcl)
    - completion: Remove providers from bash completion script (bcl)
    - completion: Filter out new headers from compose list (bcl)
    - docs: Remove unneeded Long descriptions (bcl)
    - docs: Use a custom help template (bcl)
    - docs: Add more command documentation (bcl)
    - cmdline: Add package glob support to modules list command (bcl)
    - workflow: Add govulncheck on go v1.18 (bcl)
    - tests: Update to use golangci-lint 1.49.0 (bcl)
    - New release: 35.7 (bcl)
    - spec: Move %gometa macro above %gourl (bcl)
    - weldr: When starting a compose pass size as bytes, not MiB (bcl)
    - tests: Use correct size value in bytes for test (bcl)
    - workflow: Add Go 1.18 to text matrix (bcl)
    - Replace deprecated ioutil functions (bcl)
    - New release: 35.6 (bcl)
    - tests: Update tests for osbuild-composer changes (bcl)
    - CMD: Compose status format (eloy.coto)
    - CMD: Compose list format (eloy.coto)
    - tests: Update tests to check for JSON list output (bcl)
    - composer-cli: Change JSON output to be a list of objects (bcl)
    - weldr: Simplify the old ComposeLog, etc. functions (bcl)
    - composer-cli: Add --filename to blueprints freeze save command (bcl)
    - composer-cli: Add --filename to blueprints save command (bcl)
    - composer-cli: Add --filename to compose logs command (bcl)
    - composer-cli: Add --filename to compose image command (bcl)
    - composer-cli: Add --filename to compose metadata command (bcl)
    - composer-cli: Add --filename to compose results command (bcl)
    - weldr: Add saving to a new filename to GetFilePath function (bcl)
    - github: Fix issue with codecov and forced pushes in PRs (bcl)
    - Use golangci-lint 1.45.2 in workflow (bcl)
    - Run workflow tests for go 1.16.x and 1.17.x (bcl)
    - Move go.mod to go 1.16 (bcl)
    - workflows/trigger-gitlab: run Gitlab CI in new image-builder project (jrusz)
    - Update GitHub actions/setup-go to 3
    - Update GitHub actions/checkout to 3

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2023-2780.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2880");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cockpit-composer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-composer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-composer-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-composer-dnf-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-composer-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-luks2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-lvm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-ostree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:osbuild-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-osbuild");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:weldr-client");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'cockpit-composer-45-1.0.1.el8_8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
    {'reference':'osbuild-81-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-75-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-core-75-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-dnf-json-75-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-worker-75-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-luks2-81-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-lvm2-81-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-ostree-81-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-selinux-81-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-osbuild-81-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'weldr-client-35.9-2.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-75-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-core-75-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-dnf-json-75-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-composer-worker-75-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-luks2-81-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-lvm2-81-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-ostree-81-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'osbuild-selinux-81-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-osbuild-81-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'weldr-client-35.9-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cockpit-composer / osbuild / osbuild-composer / etc');
}
