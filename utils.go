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
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os/user"
	"strings"
)

func base64Encode(b []byte) string {
	return base64.URLEncoding.EncodeToString(b)
}

func base64Decode(s string) ([]byte, error) {
	b, err := base64.URLEncoding.DecodeString(s)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	return b, nil
}

func resolvePath(s string) (resolved string) {
	parts := strings.Split(s, "/")

	username := strings.TrimPrefix(parts[0], "~")
	if username == parts[0] {
		return s
	}

	var u *user.User
	var err error
	if username == "" {
		u, err = user.Current()
	} else {
		u, err = user.Lookup(username)
	}
	if err != nil {
		return s
	}

	parts[0] = u.HomeDir
	return strings.Join(parts, "/")
}

func directoryFiles(dir string) (names []string, err error) {
	fis, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, Error.Wrap(err)
	}
	for _, fi := range fis {
		if fi.IsDir() {
			continue
		}
		names = append(names, fi.Name())
	}
	return names, nil
}

func shareLabel(share_num string) []byte {
	return []byte(fmt.Sprintf("share:%d", share_num))
}
