package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

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
	arch            string
	osName          string
	outputName      string
	tag             string
)

var (
	checksums = []string{"checksum", "md5", "sha1", "sha256", "sha512"}
	clearLine = "\033[2K\r"
	hashMap   = make(map[string]hashFile)
	macName   = []string{"darwin", "macos"}
	x32arch   = []string{"386", "x32"}
	x64arch   = []string{"amd64", "x64", "x86_64"}
)

func init() {
	flag.BoolVar(&allowPreRelease, "pre", false, "allow pre-release download")
	flag.BoolVar(&cutName, "cut", false, "cut binary filename")
	flag.BoolVar(&downloadAll, "all", false, "download all assets")
	flag.StringVar(&arch, "arch", runtime.GOARCH, "preferred CPU architecture")
	flag.StringVar(&osName, "os", runtime.GOOS, "preferred OS name")
	flag.StringVar(&outputName, "output", "", "output binary filename")
	flag.StringVar(&tag, "tag", "latest", "release tag")

	if runtime.GOOS == "windows" {
		clearLine = "\r"
	}
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

	if resp.StatusCode != http.StatusOK {
		response, _ := io.ReadAll(resp.Body)
		log.Fatalf("API request error: %s: %s", resp.Status, string(response))
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
			if stringInSlice(name, checksums) {
				content, err := getURLContent(asset.BrowserDownloadURL)
				if err != nil {
					log.Printf("error getting file contents: %s\n", err)
				}
				var hashType string
				switch {
				case strings.Contains(name, "md5"):
					hashType = "md5"
				case strings.Contains(name, "sha1"):
					hashType = "sha1"
				case strings.Contains(name, "sha256"):
					hashType = "sha256"
				case strings.Contains(name, "sha512"):
					hashType = "sha512"
				default:
					// Trying to determine the type of hashing by file extension
					hashType = strings.ToLower(strings.TrimLeft(filepath.Ext(name), "."))
				}
				// Scan lines with hashes
				var foundHash bool
				for _, line := range strings.Split(content, "\n") {
					parts := regexp.MustCompile(`\s+`).Split(line, -1)
					if len(parts) == 2 {
						foundHash = true
						// if the type of the hash is unknown then try to guess it by the length of the hash
						if hashType != "md5" || !strings.HasPrefix(hashType, "sha") {
							switch len(parts[0]) {
							case 20:
								hashType = "sha1"
							case 32:
								hashType = "md5"
							case 64:
								hashType = "sha256"
							case 128:
								hashType = "sha512"
							}
						}
						hashMap[filepath.Base(parts[1])] = hashFile{
							Hash: parts[0],
							Type: hashType,
						}
					}
				}
				if foundHash {
					log.Printf("load checksum from file %s\n", asset.Name)
				}
				continue
			}
			// Filter files by OS and architecture
			if strings.HasPrefix(asset.ContentType, "application") &&
				(strings.Contains(name, strings.ToLower(osName)) ||
					osName == "darwin" && stringInSlice(name, macName)) {
				if (arch == "amd64" && stringInSlice(name, x64arch)) ||
					(arch == "386" && stringInSlice(name, x32arch)) ||
					(arch == "arm64" && strings.Contains(name, "arm64")) ||
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

		reader := io.TeeReader(resp.Body, &writeProgress{StartTime: time.Now(), Total: asset.Size})
		var hashReader hash.Hash
		if hashFound {
			switch hashSrc.Type {
			case "md5":
				hashReader = md5.New()
			case "sha1":
				hashReader = sha1.New()
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
			err = unbzip2(reader, filepath.Join(dest, filename))
			if err != nil {
				log.Println("problem with unpack bzip2 file:", err)
			}
		case (strings.HasSuffix(asset.ContentType, "gzip") || strings.HasSuffix(asset.Name, ".gz")) &&
			!strings.HasSuffix(asset.Name, "tar.gz"):
			filename := strings.TrimSuffix(asset.Name, ".gz")
			log.Printf("unpack %s binary", filename)
			err = ungzip(reader, filepath.Join(dest, filename))
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
			err = saveFile(filepath.Join(dest, asset.Name), os.FileMode(0755), reader)
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

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func stringInSlice(s string, a []string) bool {
	s = strings.ToLower(s)
	for _, str := range a {
		if strings.Contains(s, strings.ToLower(str)) {
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
	extention := strings.TrimPrefix(strings.ToLower(ext), ".")
	switch {
	case extention == "bz2":
		zr = io.NopCloser(bzip2.NewReader(r))
	case extention == "gz" || extention == "tgz":
		zr, err = gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer zr.Close()
	default:
		return fmt.Errorf("unknown compression type: %s", extention)
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
			err := saveFile(filepath.Join(dest, filepath.Base(header.Name)), header.FileInfo().Mode(), tr)
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

			err = saveFile(filepath.Join(dest, filepath.Base(zf.Name)), os.FileMode(zf.Mode()), src)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func saveFile(destFile string, mode os.FileMode, r io.Reader) error {
	if outputName != "" {
		destFile = filepath.Join(filepath.Dir(destFile), outputName)
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
		destFile = filepath.Join(filepath.Dir(destFile), name)
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
