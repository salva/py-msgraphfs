```
NOTICE: This is alpha quality software!!!

It seems to work, but critical bugs that may cause data lost
or corruption should be expected. Use it at your own risk.
```

# Introduction

`msgraphfs` is a Linux file-system implemented on top of
[FUSE](https://www.kernel.org/doc/html/latest/filesystems/fuse.html)
for accessing OneDrive and SharePoint drives.

A `msgraphfs` file system grants access to the resources associated to
a tenant/user pair. In order to access more than one set of resources,
several instances of the file system with different configurations can
be mounted.

Currently the file system provides access to the user personal drive
(`/me`) and to the group drives (`/groups`) which are usually
associated to MS Teams teams. Access to other resources is planed

# Usage

```
python msgraphfs.py [--debug] [--debug-fuse] [resource] [mount point]
```

Example:

```
python msgraphfs.py spectre /home/esblofeld/onedrive
```

# Configuration

`msgraphfs` configuration is read from the file `~/.conf/msgraphfs.ini`

Every section in that file contains the configuration for accessing
the graph API as a particular tenant/user.

```
[spectre]
tenant_id = 0c67513c-cde9-fe90-b6ae-30143fbc76d7
application_id = adfc6dd2-bc1d-c55c-a414-adf36dd245c
application_secret = 3rnstStavro8lofe1dApp1icationSecret
authentication_callback_port = 8585
```

In order to obtain the `tenant_id`, `application_id` and
`application_secret`, you must register the application in Azure
Active Directory and create a secret.

The procedure for performing such task are available here:
https://learn.microsoft.com/en-us/azure/healthcare-apis/register-application

Note that you may need to ask some cloud admin in your organization
with the required privileges to do it for you.


# Bugs and limitations

- Access to personal OneDrive accounts doesn't work. The author
  guesses it is something related to authentication.

- Access to group drives is read only. Again, this seems to be a
  permissions issue.

- No content caching: File contents are not cached locally and so
  performance is not great.

- No dynamic updates: MS Graph provides a mechanism to receive updates
  when the remote file system changes but this program does not use
  it.

- No credential refreshing: Once the authentication token expires the
  file system stops working (the author actually knows how to handle
  that and he is working on it!).

- No universal client id/secret. Blame Microsoft on this!

- No internal locking. Locks must be used to ensure the consistence of
  the data structures used internally by the program.

- Several other unknown bugs.

Some of these bugs may be quite easy to fix, and just there because of
the author lack of knowledge about MS Graph/Azure. Feel free to
contribute!

# Installation

In the not so distance future, this program would hopefully be
available as a python package or even from your favorite Linux flavor
repositories... but not yet!

In the meantime, just download the code from the GitHub repo:
https://github.com/salva/py-msgraphfs and invoke the script in the
`src` directory directly.

# Contributing

Bug reports, feature requests or just ideas are welcome.

Also, patches and pull requests, but it you plan to do something non
trivial, you are advised to get in touch with the author first in
order to discuss the details.

# Copyright and license

Copyright (C) 2023 by Salvador Fandiño (sfandino@yahoo.com).

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/
