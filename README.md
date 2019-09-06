# get-github-release

Utility downloads and unpacks the latest binary release from GitHub

## Install

From source:

`go get -u https://github.com/n0madic/get-github-release`

## Help

```shell
Usage:
 get-github-release [-flags] <GitHub repo URL> [output path]
  -all
        download all assets
  -cut
        cut binary filename
  -output string
        output binary filename
  -pre
        allow pre-release download
  -tag string
        release tag (default "latest")
```
