Clustertests are used to test against a multi-process deployment of
Readyset that utilizes an external authority. The goal of clustertests
is to get as close to a real-world deployment as possible within the
constraints of a single machine to facilitate efficient testing.
See `DeploymentHandle` for the operations that can be performed on
the multi-process deployment.

Clustertest uses a set of environmental variables to set:
  * The path to binaries
  * The authority information
  * MySQL information.

`AUTHORITY_ADDRESS`: The address of an authority accessible from the host.
`AUTHORITY`: The authority type (consul).
`BINARY_PATH`: The path to the directory that includes readyset-server and readyset.
`MYSQL_HOST`: The address of a mysql instance accessible from the host.
`MYSQL_ROOT_PASSWORD`: The root password of the mysql instance.
