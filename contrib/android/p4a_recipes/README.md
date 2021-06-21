python-for-android local recipes
--------------------------------

These folders are recipes (build scripts) for most of our direct and transitive
dependencies for the Android app. python-for-android has recipes built-in for
many packages but it also allows users to specify their "local" recipes.
Local recipes have precedence over the built-in recipes.

The local recipes we have here are mostly just used to pin down specific
versions and hashes for reproducibility. The hashes are updated manually.
