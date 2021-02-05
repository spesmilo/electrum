Overview

Advanced Uninstall Log for NSIS was born in the need to cover a specific gap.
It's been discussed fairly enough that the File /r command is very useful
in cases when developers want to add a huge amount of sub directories and
files, nevertheless it has the disadvantage that such an installation should
be uninstalled with RmDir /r which is risky and removes also data that has
been added/created later within the installation folder.




About Advanced Uninstall Log.

Advanced Uninstall Log is a macro system provided in a NSIS header that
is able to monitor an installation and build an uninstall log file which
is used by the uninstaller to uninstall files/directories that have been
added within specific installation blocks.

This means that files which have been installed outside these blocks,
or added later either by the user or application's activities, ignored
by the uninstaller.

Moreover files that might exist into the target directory prior the current
installation, ignored as well.

Advanced Uninstall Log creates an uninstall log that removes only files that
have been installed and optionally interacts with users for every other file
and/or directory has found in installation folder and requires permission to
remove these files/directories.

It is enhanced as well to support updates, e.g. if the installer later would
update the installation by adding new data, the uninstaller would remove the
new data that has been added by the installer, without bothering users about.




Features

If target installation folder exists and contains files and/or directories
they all preserved from being uninstalled.

Uninstaller removes data that has been added within specific installation
blocks, preserving all other data that has been created/added outside of
these installation blocks. See included examples for details.

Supports unlimited updates/reinstallations.

Supports two uninstaller modes. Interactive mode requires confirmation
to remove every other file exept those files that have been installed.
Unattended mode leaves intact every other file without bothering users.

In case when uninstall log (uninstall.dat) has been removed manually instead
of execute uninstaller, if users attempt to run the installer later, a warning
issued that they should select a new output folder.

Implements only the included with NSIS release headers FileFunc and TextFunc.
There is no need for external plugins and headers, adds a very small overhead.




Restrictions

If uninstall log (uninstall.dat) is missing uninstaller won't execute at all.

Due to file create - write procedure that is required in order to add/update
the uninstall log (uninstall.dat), restricted users on NT based systems won't
be able to execute the installer.




Disadvantage

Since the header does not implement anything else than the common NSIS release,
a delay occurs while builds and reads the uninstall log because it needs to
throw the list several times. Talking for common cases, most likely the delay
won't be noticeable, however, in cases where the target directory isn't empty
and contains a large amount of data which will be excluded from uninstall log,
or added large amount of data after the installation which will be excluded also,
the delay should be noticeable.




Credits

A very big thanks goes to kichik.
When my idea of the Advanced Uninstall Log became an NSIS header, it was
indeed an amateur's attempt to write a flexible and errors free NSIS header.
Kichik dropped me a dozen of suggestions helping me to achieve my plan.
However, his main suggestion to eliminate the mentioned above disadvantage,
still remains untouched by me.




License

This header file is provided 'as-is', without any express or implied warranty.
In no event will the author be held liable for any damages arising from the use
of this header file.

Permission is granted to anyone to use this header file for any purpose,
including commercial applications, and to alter it and redistribute it freely,
subject to the following restrictions:

   1. The origin of this header file must not be misrepresented;
      you must not claim that you wrote the original header file.
      If you use this header file in a product, an acknowledgment in
      the product documentation would be appreciated but is not required.

   2. Altered versions must be plainly marked as such, and must not be
      misrepresented as being the original header file.

   3. This notice may not be removed or altered from any distribution.


eof