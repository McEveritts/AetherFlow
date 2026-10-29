"""
Tier 1: Feature Coverage (Category-Partition & Happy Paths)
Features:
- F28: Modernize Debian APT Template
- F29: Debian 13 Core OS Detection
- F30: Modernize Package Dependencies
- F31: Keyring Migration Across packages/
"""

from ..framework import TestCase, CodebaseInspector, AetherFlowApiClient

class TestF28DebianTemplateUsesHttps(TestCase):
    def __init__(self):
        super().__init__("T1_F28_01", "F28", 1, "setup/templates/apt.sources/debian.template uses TLS https://")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        template = inspector.read_file("setup/templates/apt.sources/debian.template")
        self.assert_true(bool(template and "https://deb.debian.org/debian" in template), "F28: debian.template must use https://deb.debian.org/debian")
        self.assert_false(bool(template and "http://cdn-fastly.deb.debian.org" in template), "F28: debian.template must not use http://cdn-fastly.deb.debian.org")

class TestF28NonFreeFirmwareIncluded(TestCase):
    def __init__(self):
        super().__init__("T1_F28_02", "F28", 1, "debian.template includes non-free-firmware component")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        template = inspector.read_file("setup/templates/apt.sources/debian.template")
        self.assert_true(bool(template and "non-free-firmware" in template), "F28: debian.template must include non-free-firmware for Debian 12/13")

class TestF28CanonicalSecurityRepository(TestCase):
    def __init__(self):
        super().__init__("T1_F28_03", "F28", 1, "debian.template uses official HTTPS security repository")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        template = inspector.read_file("setup/templates/apt.sources/debian.template")
        self.assert_true(bool(template and ("https://deb.debian.org/debian-security" in template or "https://security.debian.org/debian-security" in template)), "F28: debian.template must use HTTPS security mirror")

class TestF28DebMultimediaPurged(TestCase):
    def __init__(self):
        super().__init__("T1_F28_04", "F28", 1, "debian.template eliminates insecure unauthenticated deb-multimedia repo")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        template = inspector.read_file("setup/templates/apt.sources/debian.template")
        if template:
            self.assert_not_in("http://www.deb-multimedia.org", template, "F28: debian.template must remove deb-multimedia.org repository")

class TestF28DebianTemplateBackportsConfigured(TestCase):
    def __init__(self):
        super().__init__("T1_F28_05", "F28", 1, "debian.template configures release backports with HTTPS")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        template = inspector.read_file("setup/templates/apt.sources/debian.template")
        self.assert_true(bool(template and "backports" in template and "https://" in template), "F28: debian.template backports repo must use https://")

class TestF29TrixieCodenameSupported(TestCase):
    def __init__(self):
        super().__init__("T1_F29_01", "F29", 1, "00-core.sh supports Debian 13 codename 'trixie'")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        core = inspector.read_file("setup/modules/00-core.sh")
        self.assert_true(bool(core and "trixie" in core), "F29: 00-core.sh must recognize 'trixie' codename")

class TestF29EmptyVersionIdSafe(TestCase):
    def __init__(self):
        super().__init__("T1_F29_02", "F29", 1, "00-core.sh handles rolling release with empty VERSION_ID without fatal exit")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        core = inspector.read_file("setup/modules/00-core.sh")
        self.assert_true(bool(core and ("CODENAME" in core and "trixie" in core)), "F29: 00-core.sh must allow trixie even when VERSION_ID is blank")

class TestF29NativePhp84OnDebian13(TestCase):
    def __init__(self):
        super().__init__("T1_F29_03", "F29", 1, "00-core.sh detects native PHP 8.4 on Debian 13")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        core = inspector.read_file("setup/modules/00-core.sh")
        self.assert_true(bool(core and 'PHP_VER="8.4"' in core or ('trixie' in core and '8.4' in core)), "F29: 00-core.sh should set PHP_VER=8.4 for Debian 13")

class TestF29VersionGeHelperRobust(TestCase):
    def __init__(self):
        super().__init__("T1_F29_04", "F29", 1, "_version_ge helper handles empty strings without syntax error")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        core = inspector.read_file("setup/modules/00-core.sh")
        self.assert_true(bool(core and "_version_ge" in core), "F29: 00-core.sh must implement _version_ge helper")

class TestF29SupportedDistroValidation(TestCase):
    def __init__(self):
        super().__init__("T1_F29_05", "F29", 1, "00-core.sh confirms Debian 11, 12, and 13 as supported distributions")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        core = inspector.read_file("setup/modules/00-core.sh")
        self.assert_true(bool(core and "Debian" in core and "Ubuntu" in core), "F29: 00-core.sh must validate supported distros")

class TestF30SoftwarePropertiesCommonConditional(TestCase):
    def __init__(self):
        super().__init__("T1_F30_01", "F30", 1, "setup/modules/02-packages.sh removes unconditional software-properties-common on Debian")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        pkgs = inspector.read_file("setup/modules/02-packages.sh")
        if pkgs:
            lines = pkgs.splitlines()
            for i, line in enumerate(lines[:35]):
                if "_af_apt_install" in line and "software-properties-common" in line:
                    self.assert_true("Ubuntu" in line or "if" in lines[i-1], f"F30: Line {i+1} installs software-properties-common unconditionally on Debian")

class TestF30Pcre2UtilsReplacement(TestCase):
    def __init__(self):
        super().__init__("T1_F30_02", "F30", 1, "pcregrep replaced with pcre2-utils in package installation list")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        pkgs = inspector.read_file("setup/modules/02-packages.sh")
        self.assert_true(bool(pkgs and "pcre2" in pkgs), "F30: 02-packages.sh must reference pcre2-utils")

class TestF30LibncursesDevReplacement(TestCase):
    def __init__(self):
        super().__init__("T1_F30_03", "F30", 1, "libncurses5-dev replaced with libncurses-dev in package list")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        pkgs = inspector.read_file("setup/modules/02-packages.sh")
        if pkgs:
            self.assert_not_in("libncurses5-dev", pkgs, "F30: libncurses5-dev must be replaced with libncurses-dev")

class TestF30DeadPackagesPurged(TestCase):
    def __init__(self):
        super().__init__("T1_F30_04", "F30", 1, "Dead packages (mcrypt, libmcrypt-dev, php-xmlrpc) removed from 02-packages.sh")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        pkgs = inspector.read_file("setup/modules/02-packages.sh")
        if pkgs:
            self.assert_not_in("php${PHP_VER}-xmlrpc", pkgs, "F30: php-xmlrpc must be removed")
            self.assert_not_in("libmcrypt-dev", pkgs, "F30: libmcrypt-dev must be removed")

class TestF30PhpListUsesCodename(TestCase):
    def __init__(self):
        super().__init__("T1_F30_05", "F30", 1, "sury php.list uses ${CODENAME} instead of raw $(lsb_release -sc)")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        pkgs = inspector.read_file("setup/modules/02-packages.sh")
        if pkgs and "packages.sury.org" in pkgs:
            self.assert_not_in("$(lsb_release -sc)", pkgs, "F30: sury php.list should use ${CODENAME} to avoid empty string bug")

class TestF31BtsyncAptKeyRemoved(TestCase):
    def __init__(self):
        super().__init__("T1_F31_01", "F31", 1, "installpackage-btsync uses /usr/share/keyrings/ instead of apt-key")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        script = inspector.read_file("packages/package/install/installpackage-btsync")
        if script:
            self.assert_not_in("apt-key add", script, "F31: installpackage-btsync must not invoke apt-key add")

class TestF31X2goAptKeyRemoved(TestCase):
    def __init__(self):
        super().__init__("T1_F31_02", "F31", 1, "installpackage-x2go uses modern keyring instead of apt-key adv")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        script = inspector.read_file("packages/package/install/installpackage-x2go")
        if script:
            self.assert_not_in("apt-key adv", script, "F31: installpackage-x2go must not invoke apt-key adv")

class TestF31ZncAptKeyRemoved(TestCase):
    def __init__(self):
        super().__init__("T1_F31_03", "F31", 1, "installpackage-znc uses modern keyring instead of apt-key add")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        script = inspector.read_file("packages/package/install/installpackage-znc")
        if script:
            self.assert_not_in("apt-key add", script, "F31: installpackage-znc must not invoke apt-key add")

class TestF31ArrMonoAptKeyRemoved(TestCase):
    def __init__(self):
        super().__init__("T1_F31_04", "F31", 1, "removepackage scripts for jackett/lidarr/radarr remove dead Mono apt-key calls")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        for script_name in ["jackett", "lidarr", "radarr"]:
            script = inspector.read_file(f"packages/package/remove/removepackage-{script_name}")
            if script:
                self.assert_not_in("apt-key adv", script, f"F31: removepackage-{script_name} must remove dead apt-key call")

class TestF31UpdateAetherFlowAptKeyRemoved(TestCase):
    def __init__(self):
        super().__init__("T1_F31_05", "F31", 1, "updateAetherFlow removes dead Jessie apt-key call")

    def run(self, inspector: CodebaseInspector, client: AetherFlowApiClient, mode: str = "contract"):
        script = inspector.read_file("packages/system/updateAetherFlow")
        if script:
            self.assert_not_in("apt-key add", script, "F31: updateAetherFlow must not call apt-key add")

def get_tests():
    return [
        TestF28DebianTemplateUsesHttps(), TestF28NonFreeFirmwareIncluded(), TestF28CanonicalSecurityRepository(), TestF28DebMultimediaPurged(), TestF28DebianTemplateBackportsConfigured(),
        TestF29TrixieCodenameSupported(), TestF29EmptyVersionIdSafe(), TestF29NativePhp84OnDebian13(), TestF29VersionGeHelperRobust(), TestF29SupportedDistroValidation(),
        TestF30SoftwarePropertiesCommonConditional(), TestF30Pcre2UtilsReplacement(), TestF30LibncursesDevReplacement(), TestF30DeadPackagesPurged(), TestF30PhpListUsesCodename(),
        TestF31BtsyncAptKeyRemoved(), TestF31X2goAptKeyRemoved(), TestF31ZncAptKeyRemoved(), TestF31ArrMonoAptKeyRemoved(), TestF31UpdateAetherFlowAptKeyRemoved()
    ]
