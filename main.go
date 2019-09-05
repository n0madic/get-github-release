package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	ContentType        string `json:"content_type"`
	Size               int    `json:"size"`
}

type release struct {
	Assets     []asset
	PreRelease bool `json:"prerelease"`
}

type hashFile struct {
	Hash string
	Type string
}

var (
	allowPreRelease bool
	cutName         bool
	downloadAll     bool
	outputName      string
	tag             string
)

var (
	hashMap = make(map[string]hashFile)
	x32arch = []string{"386", "x32"}
	x64arch = []string{"amd64", "x64", "x86_64"}
)

func init() {
	flag.BoolVar(&allowPreRelease, "pre", false, "allow pre-release download")
	flag.BoolVar(&cutName, "cut", false, "cut binary filename")
	flag.BoolVar(&downloadAll, "all", false, "download all assets")
	flag.StringVar(&outputName, "output", "", "output binary filename")
	flag.StringVar(&tag, "tag", "latest", "release tag")
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Downloads the latest binary release from GitHub\n\nUsage:\n")
		fmt.Fprintf(os.Stderr, " %s [-flags] <GitHub repo URL> [output path]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// If no link to the repository is specified
	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	dest := "."
	if flag.NArg() > 1 {
		dest = flag.Args()[1]
	}

	stat, err := os.Stat(dest)
	if err != nil {
		log.Fatal("output path error:", err)
	}
	if !stat.IsDir() {
		log.Fatalf("output path %s is not directory", dest)
	}
	strings.TrimRight(dest, "/")

	parts := strings.Split(strings.TrimPrefix(flag.Args()[0], "https://github.com/"), "/")
	if len(parts) < 2 {
		log.Fatal("require valid GitHub repo URL")
	}
	owner := parts[0]
	project := parts[1]

	repoURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", owner, project)

	// If there is a link to a tagged release
	if len(parts) == 5 && parts[3] == "tag" {
		tag = parts[4]
	}
	if tag != "latest" {
		repoURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/tags/%s", owner, project, tag)
	}

	// If there is a link to a pre-release
	if allowPreRelease {
		repoURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/releases", owner, project)
	}

	// GitHub API request
	resp, err := http.Get(repoURL)
	if err != nil {
		log.Fatal(err)
	}

	var latest release
	if allowPreRelease {
		// Download the whole list of releases and take the first
		var releaseList []release
		err = json.NewDecoder(resp.Body).Decode(&releaseList)
		if err != nil {
			log.Fatal(err)
		}
		if len(releaseList) > 0 {
			latest = releaseList[0]
		}
	} else {
		err = json.NewDecoder(resp.Body).Decode(&latest)
		if err != nil {
			log.Fatal(err)
		}
	}

	var downloads []asset
	if downloadAll {
		downloads = latest.Assets
	} else {
		var candidate asset
		for _, asset := range latest.Assets {
			name := strings.ToLower(asset.Name)
			// If checksum files are found, try to download them
			if strings.Contains(name, "checksum") || strings.HasSuffix(name, ".md5") || strings.HasSuffix(name, ".sha256") {
				content, err := getURLContent(asset.BrowserDownloadURL)
				if err != nil {
					log.Printf("error getting file contents: %s\n", err)
				}
				// Trying to determine the type of hashing by file extension
				hashType := strings.ToLower(strings.TrimLeft(filepath.Ext(name), "."))
				// Scan lines with hashes
				for _, line := range strings.Split(content, "\n") {
					parts := regexp.MustCompile(`\s+`).Split(line, -1)
					if len(parts) == 2 {
						// if the type of the hash is unknown then try to guess it by the length of the hash
						if hashType != "md5" || !strings.HasPrefix(hashType, "sha") {
							if len(parts[0]) == 32 {
								hashType = "md5"
							} else if len(parts[0]) == 64 {
								hashType = "sha256"
							}
						}
						hashMap[filepath.Base(parts[1])] = hashFile{
							Hash: parts[0],
							Type: hashType,
						}
					}
				}
				continue
			}
			// Filter files by OS and architecture
			if strings.HasPrefix(asset.ContentType, "application") &&
				strings.Contains(name, runtime.GOOS) {
				if (runtime.GOARCH == "amd64" && isArch(name, x64arch)) ||
					(runtime.GOARCH == "386" && isArch(name, x32arch)) ||
					candidate.Name == "" {
					candidate = asset
				}
			}
		}
		if candidate.Name != "" {
			downloads = append(downloads, candidate)
		} else {
			log.Fatal("No downloads found suitable for this system")
		}
	}

	for _, asset := range downloads {
		log.Printf("download URL: %s (%d MB)\n", asset.BrowserDownloadURL, asset.Size/1024/1024)
		resp, err := http.Get(asset.BrowserDownloadURL)
		if err != nil {
			log.Println(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("bad status: %s\n", resp.Status)
		}

		hashSrc, hashFound := hashMap[asset.Name]

		var reader io.Reader
		reader = resp.Body
		var hashReader hash.Hash
		if hashFound {
			switch hashSrc.Type {
			case "md5":
				hashReader = md5.New()
			case "sha256":
				hashReader = sha256.New()
			case "sha512":
				hashReader = sha512.New()
			default:
				log.Printf("unknown hash type: %s\n", hashSrc.Type)
			}
			if hashReader != nil {
				reader = io.TeeReader(resp.Body, hashReader)
			}
		}

		switch {
		case strings.HasSuffix(asset.ContentType, "gzip") || strings.HasSuffix(asset.Name, "gz"):
			err = untar(reader, dest)
			if err != nil {
				log.Println("problem with untar file:", err)
			}
		case strings.HasSuffix(asset.ContentType, "zip") || strings.HasSuffix(asset.Name, "zip"):
			err = unzip(reader, dest)
			if err != nil {
				log.Println("problem with unzip file:", err)
			}
		default:
			log.Printf("unknow content type: %s, try to just download", asset.ContentType)
			err = saveFile(dest+"/"+asset.Name, os.FileMode(0755), reader)
			if err != nil {
				log.Println("problem with download file:", err)
			}
		}

		if hashReader != nil {
			checkResult := fmt.Sprintf("checksum of a %s file: ", asset.Name)
			if hashSrc.Hash == hex.EncodeToString(hashReader.Sum(nil)) {
				checkResult += "OK"
			} else {
				checkResult += "FAIL"
			}
			log.Println(checkResult)
		}

	}

}

func getURLContent(url string) (string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("bad status: %s", resp.Status)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func isArch(s string, a []string) bool {
	for _, arch := range a {
		if strings.Contains(s, arch) {
			return true
		}
	}
	return false
}

func isExecutable(m os.FileMode) bool {
	return m&(1<<6) != 0
}

func untar(r io.Reader, dest string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()

		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case header == nil:
			continue
		}

		if !header.FileInfo().IsDir() {
			if isExecutable(header.FileInfo().Mode()) {
				log.Printf("unpack %s binary", header.Name)
				err := saveFile(dest+"/"+header.Name, header.FileInfo().Mode(), tr)
				if err != nil {
					return err
				}
			}
		}
	}
}

func unzip(r io.Reader, dest string) error {
	buff := bytes.NewBuffer([]byte{})
	size, err := io.Copy(buff, r)
	if err != nil {
		return err
	}

	reader := bytes.NewReader(buff.Bytes())

	z, err := zip.NewReader(reader, size)
	if err != nil {
		return err
	}

	for _, zf := range z.File {
		if isExecutable(zf.Mode()) {
			log.Printf("unpack %s binary", zf.Name)

			src, err := zf.Open()
			if err != nil {
				return err
			}
			defer src.Close()

			err = saveFile(dest+"/"+zf.Name, os.FileMode(zf.Mode()), src)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func saveFile(destFile string, mode os.FileMode, r io.Reader) error {
	if outputName != "" {
		destFile = filepath.Dir(destFile) + "/" + outputName
	} else if cutName {
		// Cropping the file name to the first part
		parts := strings.FieldsFunc(destFile, func(r rune) bool {
			return r == '-' || r == '_' || r == ' '
		})
		ext := filepath.Ext(destFile)
		destFile = parts[0]
		if !strings.HasSuffix(destFile, ".exe") && strings.ToLower(ext) == ".exe" {
			destFile += ".exe"
		}
	}

	f, err := os.OpenFile(destFile, os.O_CREATE|os.O_RDWR, os.FileMode(mode))
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		return err
	}

	return nil
}