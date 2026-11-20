#!/usr/bin/env python3
"""Regenerates gradle-verification-metadata.xml: the sha256 of every file gradle downloads
during the apk build, that is the android gradle plugin and its dependencies.
https://docs.gradle.org/9.4.1/userguide/dependency_verification.html

Run it through update_gradle_verification_metadata.sh, as it needs the build container.

The gradle project of the apk only exists at the end of an apk build. So instead, this builds
a minimal app with the gradle files that python-for-android would generate for a
buildozer.spec that adds no gradle dependencies, like ours.
"""
import os
import shutil
import subprocess
import tempfile
from types import SimpleNamespace

import jinja2
import pythonforandroid

CONTRIB_ANDROID = os.path.dirname(os.path.abspath(__file__))
METADATA = os.path.join(CONTRIB_ANDROID, "gradle-verification-metadata.xml")
P4A_BUILD_DIR = os.path.join(os.path.dirname(pythonforandroid.__file__), "bootstraps", "common", "build")

SDK_DIR = os.environ["ANDROID_SDK_HOME"]
ANDROID_API = os.environ["ANDROID_SDK_BUILD_TOOLS_MAJOR_V"]
BUILD_TOOLS_VERSION = os.environ["ANDROID_SDK_BUILD_TOOLS_VERSION"]

MANIFEST = """\
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".Main" android:exported="true"/>
    </application>
</manifest>
"""

ACTIVITY = """\
package org.electrum.gradledeps;

public class Main extends android.app.Activity {}
"""


def write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def create_project(project_dir: str) -> None:
    shutil.copytree(os.path.join(P4A_BUILD_DIR, "gradle"), os.path.join(project_dir, "gradle"))
    shutil.copy(os.path.join(P4A_BUILD_DIR, "gradlew"), project_dir)
    templates = jinja2.Environment(
        loader=jinja2.FileSystemLoader(os.path.join(P4A_BUILD_DIR, "templates")),
        undefined=jinja2.StrictUndefined,  # fail if python-for-android adds an option we do not set here
    )
    args = SimpleNamespace(
        package="org.electrum.gradledeps",
        version="1",
        numeric_version=1,
        min_sdk_version=ANDROID_API,  # the sdk versions do not change what gradle downloads
        android_target_sdk_version=ANDROID_API,
        manifest_placeholders="[:]",
        sign=False,
        gradle_repositories=[],
        depends=[],
        presplash_lottie=None,
        enable_androidx=False,
        packaging_options=[],
        compile_options=[],
        extra_source_dirs=[],
    )
    write(os.path.join(project_dir, "build.gradle"), templates.get_template("build.tmpl.gradle").render(
        args=args, aars=[], jars=[], android_api=ANDROID_API, build_tools_version=BUILD_TOOLS_VERSION,
        debug_build=False, is_library=False))
    write(os.path.join(project_dir, "gradle.properties"), templates.get_template("gradle.tmpl.properties").render(
        args=args))
    write(os.path.join(project_dir, "local.properties"), f"sdk.dir={SDK_DIR}")
    write(os.path.join(project_dir, "src/main/AndroidManifest.xml"), MANIFEST)
    write(os.path.join(project_dir, "src/main/java/org/electrum/gradledeps/Main.java"), ACTIVITY)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp_dir:
        project_dir = os.path.join(tmp_dir, "project")
        create_project(project_dir)
        # an empty gradle home, so that the hashes are those of files downloaded just now
        env = {**os.environ, "GRADLE_USER_HOME": os.path.join(tmp_dir, "gradle_home")}
        subprocess.run(
            ["./gradlew", "--no-daemon", "--write-verification-metadata", "sha256",
             "clean", "assembleRelease", "assembleDebug"],
            cwd=project_dir, env=env, check=True)
        shutil.copy(os.path.join(project_dir, "gradle", "verification-metadata.xml"), METADATA)
    print(f"updated {METADATA}")


if __name__ == "__main__":
    main()
