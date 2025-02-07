package main

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	dregistry "github.com/rusenask/docker-registry-client/registry"
	yaml "gopkg.in/yaml.v3"
)

type DrLatestYamlItem struct {
	KeyPrefix        string `yaml:"KeyPrefix"`
	KeyPrefixReplace string `yaml:"KeyPrefixReplace"`
	RegistryUsername string `yaml:"RegistryUsername"`
	RegistryPassword string `yaml:"RegistryPassword"`
}

type DrVersions []string

func (vv DrVersions) Len() int {
	return len(vv)
}

func (vv DrVersions) Less(i, j int) bool {
	v1, v2 := vv[i], vv[j]
	v1s := strings.Split(v1, ".")
	v2s := strings.Split(v2, ".")
	if len(v1s) < len(v2s) {
		return true
	} else if len(v1s) > len(v2s) {
		return false
	}
	for e := 0; e < len(v1s); e++ {
		d1, _ := strconv.Atoi(v1s[e])
		d2, _ := strconv.Atoi(v2s[e])
		if d1 < d2 {
			return true
		} else if d1 > d2 {
			return false
		}
	}
	return false
}

func (vv DrVersions) Swap(i, j int) {
	vv[i], vv[j] = vv[j], vv[i]
}

func drlatestyaml(helmvalues map[string]interface{}, drlatestyamlitems []DrLatestYamlItem, imagesvalues *map[string]interface{}) (err error) {
	for helmvalueskey, helmvaluesvalue := range helmvalues {
		//log("drlatestyaml helmvalueskey %s", helmvalueskey)
		for _, e := range drlatestyamlitems {
			//log("  drlatestyaml KeyPrefix %s", e.KeyPrefix)
			if strings.HasPrefix(helmvalueskey, e.KeyPrefix) {
				//log("drlatestyaml %s HasPrefix %s", helmvalueskey, e.KeyPrefix)

				imagename := helmvalueskey
				imageurl := helmvaluesvalue.(string)

				if !strings.HasPrefix(imageurl, "https://") && !strings.HasPrefix(imageurl, "http://") {
					imageurl = fmt.Sprintf("https://%s", imageurl)
				}

				var u *url.URL
				if u, err = url.Parse(imageurl); err != nil {
					return fmt.Errorf("url.Parse %s %v: %w", imagename, imageurl, err)
				}

				RegistryUrl := fmt.Sprintf("%s://%s", u.Scheme, u.Host)
				RegistryRepository := u.Path

				//log("drlatestyaml registry %s %s", RegistryUrl, RegistryRepository)

				r := dregistry.NewInsecure(RegistryUrl, e.RegistryUsername, e.RegistryPassword)
				r.Logf = dregistry.Quiet

				imagetags, err := r.Tags(RegistryRepository)
				if err != nil {
					return fmt.Errorf("registry.Tags %s %v: %w", imagename, imageurl, err)
				}

				sort.Sort(sort.Reverse(DrVersions(imagetags)))

				imagetag := ""

				if len(imagetags) > 0 {
					imagetag = imagetags[0]
				} else {
					imagetag = "latest"
				}

				imagenamereplace := e.KeyPrefixReplace + strings.TrimPrefix(imagename, e.KeyPrefix)
				(*imagesvalues)[imagenamereplace] = imagetag

				//log("drlatestyaml %s %s", imagenamereplace, imagetag)
			}
		}
	}

	return nil
}

func ImagesValuesToList(imagesvaluesmap map[string]interface{}) (imagesvalueslist []map[string]interface{}, imagesvaluestext string, err error) {
	imagesvalueslist = make([]map[string]interface{}, 0)
	for k, v := range imagesvaluesmap {
		imagesvalueslist = append(imagesvalueslist, map[string]interface{}{k: v})
	}
	sort.Slice(
		imagesvalueslist,
		func(i, j int) bool {
			for ik := range imagesvalueslist[i] {
				for jk := range imagesvalueslist[j] {
					return ik < jk
				}
			}
			return false
		},
	)

	for _, iv := range imagesvalueslist {
		if bb, err := yaml.Marshal(iv); err != nil {
			return nil, "", fmt.Errorf("yaml.Encoder: %w", err)
		} else {
			imagesvaluestext += string(bb) + NL
		}
	}

	return imagesvalueslist, imagesvaluestext, nil
}
