// Copyright (C) 2016 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gfbank

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
)

const (
	stem = "data"
)

var (
	// shares are in the form data.NNN
	sharesRE = regexp.MustCompile(`^` + stem + `.(\d{3})$`)
)

type Share struct {
	Number string
	Data   []byte
}

func SplitString(data string, n, m int) (shares []Share, err error) {
	return SplitBytes([]byte(data), n, m)
}

func SplitBytes(data []byte, n, m int) (shares []Share, err error) {
	dir, err := ioutil.TempDir("", "gfbank-")
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() {
		os.RemoveAll(dir)
	}()

	err = ioutil.WriteFile(filepath.Join(dir, stem), data, 0600)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	var stderr bytes.Buffer
	cmd := exec.Command("gfsplit",
		"-n", fmt.Sprint(n),
		"-m", fmt.Sprint(m),
		"data")
	cmd.Stderr = &stderr
	cmd.Dir = dir
	err = cmd.Run()
	if err != nil {
		return nil, Error.New("gfsplit failed: %s", stderr.String())
	}

	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, Error.Wrap(err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == stem {
			continue
		}
		m := sharesRE.FindStringSubmatch(name)
		if m == nil {
			continue
		}

		data, err := ioutil.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, Error.New("unable to read share data on %q: %v",
				name, err)
		}

		shares = append(shares, Share{
			Number: m[1],
			Data:   data,
		})
	}

	if len(shares) != m {
		return nil, Error.New("expected %d shares; got %d", m, len(shares))
	}

	return shares, nil
}

func CombineString(shares []Share) (data string, err error) {
	data_bytes, err := CombineBytes(shares)
	return string(data_bytes), err
}

func CombineBytes(shares []Share) (data []byte, err error) {
	dir, err := ioutil.TempDir("", "gfbank-")
	if err != nil {
		return nil, Error.Wrap(err)
	}
	defer func() {
		os.RemoveAll(dir)
	}()

	args := []string{"-o", stem}
	for _, share := range shares {
		inputfile := fmt.Sprintf("%s.%s", stem, share.Number)
		args = append(args, inputfile)
		err = ioutil.WriteFile(
			filepath.Join(dir, inputfile), share.Data, 0600)
		if err != nil {
			return nil, Error.Wrap(err)
		}
	}

	cmd := exec.Command("gfcombine", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, Error.New("gfcombine failed: %q %v", string(out), err)
	}

	data, err = ioutil.ReadFile(filepath.Join(dir, stem))
	if err != nil {
		return nil, Error.New("unable to read combined data: %v", err)
	}
	return data, nil
}
