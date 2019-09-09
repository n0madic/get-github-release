package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
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
	"time"
)

const clearLine = "\033[2K\r"

type asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	ContentType        string `json:"content_type"`
	Size               int64  `json:"size"`
}

type release struct {
	Assets     []asset
	PreRelease bool `json:"prerelease"`
}

type hashFile struct {
	Hash string
	Type string
}

type writeProgress struct {
	downloaded  int64
	lastPercent int
	StartTime   time.Time
	Total       int64
}

func (wp *writeProgress) Write(p []byte) (int, error) {
	n := len(p)
	wp.downloaded += int64(n)
	ratio := float64(wp.downloaded) / float64(wp.Total)
	percent := int(100 * ratio)
	if percent > wp.lastPercent {
		total := time.Duration(float64(time.Since(wp.StartTime)) / ratio)
		var remaining string
		if percent > 1 {
			remaining = fmt.Sprintf("%v remaining...",
				time.Until(wp.StartTime.Add(total)).Round(time.Second),
			)
		}
		fmt.Fprintf(os.Stderr, "%s=> Download %s/%s (%d%%) %s",
			clearLine,
			byteHumanize(wp.downloaded),
			byteHumanize(wp.Total),
			percent,
			remaining,
		)
	}
	wp.lastPercent = percent
	return n, nil
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

	log.SetPrefix(clearLine)
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
	dest = strings.TrimRight(dest, "/")

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
				log.Printf("load checksum from file %s\n", asset.Name)
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
		log.Printf("download URL: %s (%s)\n", asset.BrowserDownloadURL, byteHumanize(asset.Size))
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
		reader = io.TeeReader(resp.Body, &writeProgress{StartTime: time.Now(), Total: asset.Size})
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
				reader = io.TeeReader(reader, hashReader)
			}
		}

		switch {
		case (strings.HasSuffix(asset.ContentType, "bzip2") || strings.HasSuffix(asset.Name, ".bz2")) &&
			!strings.HasSuffix(asset.Name, "tar.bz2"):
			filename := strings.TrimSuffix(asset.Name, ".bz2")
			log.Printf("unpack %s binary", filename)
			err = unbzip2(reader, dest+"/"+filename)
			if err != nil {
				log.Println("problem with unpack bzip2 file:", err)
			}
		case (strings.HasSuffix(asset.ContentType, "gzip") || strings.HasSuffix(asset.Name, ".gz")) &&
			!strings.HasSuffix(asset.Name, "tar.gz"):
			filename := strings.TrimSuffix(asset.Name, ".gz")
			log.Printf("unpack %s binary", filename)
			err = ungzip(reader, dest+"/"+filename)
			if err != nil {
				log.Println("problem with unpack gzip file:", err)
			}

		case strings.HasSuffix(asset.Name, "tgz") || strings.HasSuffix(asset.Name, "tar.gz") ||
			strings.HasSuffix(asset.Name, "tar.bz2"):
			err = untar(reader, filepath.Ext(asset.Name), dest)
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

	fmt.Fprintf(os.Stderr, "%s", clearLine)
}

func byteHumanize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
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

func unbzip2(r io.Reader, dest string) error {
	return saveFile(dest, os.FileMode(0755), bzip2.NewReader(r))
}

func ungzip(r io.Reader, dest string) error {
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	err = saveFile(dest, os.FileMode(0755), gzr)
	if err != nil {
		return err
	}

	return nil
}

func untar(r io.Reader, ext, dest string) (err error) {
	var zr io.ReadCloser
	switch strings.ToLower(ext) {
	case ".bz2":
		zr = ioutil.NopCloser(bzip2.NewReader(r))
	case ".gz":
		zr, err = gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer zr.Close()
	default:
		log.Printf("unknown compression type: %s\n", strings.TrimPrefix(ext, "."))
	}

	tr := tar.NewReader(zr)
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

		if !header.FileInfo().IsDir() && isExecutable(header.FileInfo().Mode()) {
			log.Printf("unpack %s binary", header.Name)
			err := saveFile(dest+"/"+filepath.Base(header.Name), header.FileInfo().Mode(), tr)
			if err != nil {
				return err
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
		if !zf.FileInfo().IsDir() && isExecutable(zf.Mode()) {
			log.Printf("unpack %s binary", zf.Name)

			src, err := zf.Open()
			if err != nil {
				return err
			}
			defer src.Close()

			err = saveFile(dest+"/"+filepath.Base(zf.Name), os.FileMode(zf.Mode()), src)
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
		log.Println("> save as", outputName)
	} else if cutName {
		// cropping the file name to the first part
		name := filepath.Base(destFile)
		parts := strings.FieldsFunc(name, func(r rune) bool {
			return r == '-' || r == '_' || r == ' '
		})
		ext := filepath.Ext(name)
		name = parts[0]
		if !strings.HasSuffix(name, ".exe") && strings.ToLower(ext) == ".exe" {
			name += ".exe"
		}
		log.Println("> save as", name)
		destFile = filepath.Dir(destFile) + "/" + name
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
