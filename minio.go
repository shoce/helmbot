package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"
)

// get/put values file from/to a minio storage
// https://gist.github.com/gabo89/5e3e316bd4be0fb99369eac512a66537
// https://stackoverflow.com/questions/72047783/how-do-i-download-files-from-a-minio-s3-bucket-using-curl
func MinioNewRequest(method, name string, payload []byte) (r *http.Request, err error) {
	r, err = http.NewRequest(method, ValuesMinioUrl+name, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	r.Header.Set("User-Agent", "helmbot")
	r.Header.Set("Content-Type", "application/octet-stream")
	r.Header.Set("Host", ValuesMinioUrl)
	r.Header.Set("Date", time.Now().UTC().Format(time.RFC1123Z))

	hdrauthsig := method + NL + NL + r.Header.Get("Content-Type") + NL + r.Header.Get("Date") + NL + ValuesMinioUrlPath + name
	hdrauthsighmac := hmac.New(sha1.New, []byte(ValuesMinioPassword))
	hdrauthsighmac.Write([]byte(hdrauthsig))
	hdrauthsig = base64.StdEncoding.EncodeToString(hdrauthsighmac.Sum(nil))
	r.Header.Set("Authorization", fmt.Sprintf("AWS %s:%s", ValuesMinioUsername, hdrauthsig))

	return r, nil
}

func GetValuesTextMinio(name string, valuestext *string) (err error) {
	r, err := MinioNewRequest(http.MethodGet, name, nil)

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return err
	}

	valuesbytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	*valuestext = string(valuesbytes)

	if DEBUG {
		log("DEBUG GetValuesTextMinio %s [len %d]: %s...", name, len(*valuestext), strings.ReplaceAll((*valuestext), NL, " <nl> "))
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("minio server response status %s", resp.Status)
	}

	return nil
}

func GetValuesMinio(name string, valuestext *string, values interface{}) (err error) {
	if valuestext == nil {
		var valuestext1 string
		valuestext = &valuestext1
	}

	err = GetValuesTextMinio(name, valuestext)
	if err != nil {
		return err
	}

	d := yaml.NewDecoder(strings.NewReader(*valuestext))
	err = d.Decode(values)
	if err != nil {
		return err
	}

	return nil
}

func PutValuesTextMinio(name string, valuestext string) (err error) {
	r, err := MinioNewRequest(http.MethodPut, name, []byte(valuestext))

	if DEBUG {
		log("DEBUG PutValuesTextMinio %s [len %d]: %s...", name, len(valuestext), strings.ReplaceAll((valuestext), NL, " <nl> "))
	}

	resp, err := http.DefaultClient.Do(r)
	log("DEBUG PutValuesTextMinio resp.Status: %s", resp.Status)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("minio server response status %s", resp.Status)
	}

	return nil
}
