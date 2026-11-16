"""Hook for python-for-android, see "p4a.hook" in the buildozer spec.

The manifest template of p4a can only declare the services that p4a itself generates, and those
cannot have a permission. We need a JobService, which the OS only runs if it requires the
permission BIND_JOB_SERVICE, and a service that runs python when it gets bound.
See electrum/gui/qml/java_classes/org/electrum/gossip/.
"""
import os

SERVICES = '''
        <service android:name="org.electrum.gossip.GossipSyncJobService"
                 android:permission="android.permission.BIND_JOB_SERVICE"
                 android:exported="true" />
        <service android:name="org.electrum.gossip.GossipSyncService"
                 android:process=":gossipsync"
                 android:exported="false" />
'''


def after_apk_build(toolchain):
    # called after the manifest got rendered and before gradle runs, with the dist dir as cwd
    path = os.path.join('src', 'main', 'AndroidManifest.xml')
    with open(path, encoding='utf-8') as f:
        manifest = f.read()
    assert 'org.electrum.gossip' not in manifest, "services already declared?"
    assert manifest.count('</application>') == 1, "unexpected manifest"
    manifest = manifest.replace('</application>', SERVICES + '    </application>')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(manifest)
