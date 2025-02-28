# get-github-release

Utility downloads and unpacks the latest binary release from GitHub

## Install

From source:

`go install github.com/n0madic/get-github-release@latest`

## Help

```shell
Usage:
 get-github-release [-flags] <GitHub repo URL> [output path]

Flags:
  -all
    	download all assets
  -arch string
    	preferred CPU architecture (default "arm64")
  -cut
    	cut binary filename
  -os string
    	preferred OS name (default "darwin")
  -output string
    	output binary filename
  -pre
    	allow pre-release download
  -tag string
    	release tag (default "latest")
```
