# treeify

Processing information from [Trustify](https://github.com/trustifification/trustify).

## What is it for?

Taking the output of `/api/v2/analysis/component` and `/api/v2/analysis/latest/component` and trying to make sense of
it.

The idea is to use something like `http` or `curl` and store the result of such queries in a file. And then use this
cool to process this data.

## What does it do?

Right now, it can:

* Fetch all referenced SBOMs and store them locally
* Convert the graph into GEFX and GraphML for using it with other visualization tools
* Convert the graph into a GraphViz DOT file
