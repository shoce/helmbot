/*

GoFmt
GoBuildNull

go get -u -v gopkg.in/yaml.v3
go get -u -v helm.sh/helm/v3
go get -u -v github.com/rusenask/docker-registry-client/registry
go get -u -v k8s.io/api/core/v1 k8s.io/apimachinery/pkg/api/errors k8s.io/apimachinery/pkg/apis/meta/v1 k8s.io/client-go/kubernetes k8s.io/client-go/rest
go get -a -u -v
go mod tidy

*/

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "time/tzdata"

	yaml "gopkg.in/yaml.v3"

	helmaction "helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmloader "helm.sh/helm/v3/pkg/chart/loader"
	helmcli "helm.sh/helm/v3/pkg/cli"
	helmdownloader "helm.sh/helm/v3/pkg/downloader"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmrelease "helm.sh/helm/v3/pkg/release"
	helmrepo "helm.sh/helm/v3/pkg/repo"

	dregistry "github.com/rusenask/docker-registry-client/registry"

	kcorev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	kmetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	krest "k8s.io/client-go/rest"
)

const (
	SPAC = "    "
	TAB  = "\t"
	NL   = "\n"

	ServerPackagesUpgradeInterval = 43 * time.Second

	UpdateHashIdReString = "#([-a-z]+)#([-a-z]+)#([a-z0-9]+)$"

	ValuesLatestHashFilenameSuffix   = "values.latest.hash.text"
	ValuesDeployedHashFilenameSuffix = "values.deployed.hash.text"
	ValuesReportedHashFilenameSuffix = "values.reported.hash.text"
	PermitHashFilenameSuffix         = "values.permit.hash.text"
)

var (
	DEBUG bool

	LogUTCTime bool

	LocalZone string

	UpdateHashIdRe *regexp.Regexp

	ServerHostname string
	PackagesDir    string

	ConfigLocalDir      string
	ConfigLocalFilename string
	ConfigMinioFilename string

	Config HelmbotConfig

	ListenAddr string

	TgToken                 string
	TgBotUserId             int64
	TgWebhookHost           string
	TgWebhookUrl            string
	TgWebhookToken          string
	TgWebhookMaxConnections int64 = 1

	TgChatIds             []int64
	TgBossUserIds         []int64
	TgParseMode           = "MarkdownV2"
	TgDisableNotification = false

	GetValuesUrlPrefix     string
	GetValuesUrlHost       string
	GetValuesUrlPrefixPath string
	GetValuesUsername      string
	GetValuesPassword      string

	PutValuesUrlPrefix     string
	PutValuesUrlHost       string
	PutValuesUrlPrefixPath string
	PutValuesUsername      string
	PutValuesPassword      string
)

func init() {
	var err error

	LocalZone = time.Now().Local().Format("-0700")

	UpdateHashIdRe, err = regexp.Compile(UpdateHashIdReString)
	if err != nil {
		log("ERROR %v regexp compile error: %s", UpdateHashIdReString, err)
		os.Exit(1)
	}

	if os.Getenv("DEBUG") != "" {
		DEBUG = true
	}

	ServerHostname = os.Getenv("ServerHostname")
	if ServerHostname == "" {
		log("ERROR Empty ServerHostname env var")
		os.Exit(1)
	}

	PackagesDir = os.Getenv("PackagesDir")
	if PackagesDir == "" {
		log("ERROR Empty PackagesDir env var")
		os.Exit(1)
	}

	ConfigLocalDir = os.Getenv("ConfigLocalDir")
	ConfigLocalFilename = os.Getenv("ConfigLocalFilename")
	ConfigMinioFilename = os.Getenv("ConfigMinioFilename")

	ListenAddr = os.Getenv("ListenAddr")
	if ListenAddr == "" {
		ListenAddr = ":80"
	}

	TgToken = os.Getenv("TgToken")
	if TgToken == "" {
		log("ERROR Empty TgToken env var")
		os.Exit(1)
	}

	if TgToken != "" {
		botuserid := strings.Split(TgToken, ":")[0]
		userid, err := strconv.Atoi(botuserid)
		if err != nil {
			log("ERROR Invalid bot user id:`%s`", botuserid)
			os.Exit(1)
		}
		TgBotUserId = int64(userid)
	}
	if TgBotUserId == 0 {
		log("ERROR Empty or invalid bot user id")
		os.Exit(1)
	}

	TgWebhookHost = os.Getenv("TgWebhookHost")
	if TgWebhookHost == "" {
		log("WARNING Empty TgWebhookHost env var")
	}

	TgWebhookUrl = os.Getenv("TgWebhookUrl")
	if TgWebhookUrl == "" {
		log("WARNING Empty TgWebhookUrl env var")
	}

	TgWebhookToken = os.Getenv("TgWebhookToken")
	if TgWebhookToken == "" {
		log("WARNING Empty TgWebhookToken env var")
	}

	for _, i := range strings.Split(strings.TrimSpace(os.Getenv("TgChatIds")), " ") {
		if i == "" {
			continue
		}
		chatid, err := strconv.Atoi(i)
		if err != nil || chatid == 0 {
			log("WARNING Invalid chat id:`%s`", i)
		}
		TgChatIds = append(TgChatIds, int64(chatid))
	}
	if len(TgChatIds) == 0 {
		log("ERROR Empty or invalid TgChatIds env var")
		os.Exit(1)
	}

	for _, i := range strings.Split(strings.TrimSpace(os.Getenv("TgBossUserIds")), " ") {
		if i == "" {
			continue
		}
		userid, err := strconv.Atoi(i)
		if err != nil || userid == 0 {
			log("WARNING Invalid user id `%s`", i)
		}
		TgBossUserIds = append(TgBossUserIds, int64(userid))
	}
	if len(TgBossUserIds) == 0 {
		log("WARNING Empty or invalid TgBossUserIds env var")
	}

	GetValuesUrlPrefix = os.Getenv("GetValuesUrlPrefix")
	if GetValuesUrlPrefix == "" {
		log("ERROR Empty GetValuesUrlPrefix env var")
		os.Exit(1)
	}
	if getvaluesurl, err := url.Parse(GetValuesUrlPrefix); err != nil {
		log("ERROR url.Parse GetValuesUrlPrefix: %v", err)
		os.Exit(1)
	} else {
		GetValuesUrlHost = getvaluesurl.Host
		GetValuesUrlPrefixPath = getvaluesurl.Path
	}

	GetValuesUsername = os.Getenv("GetValuesUsername")
	if GetValuesUsername == "" {
		log("ERROR Empty GetValuesUsername env var")
		os.Exit(1)
	}

	GetValuesPassword = os.Getenv("GetValuesPassword")
	if GetValuesPassword == "" {
		log("ERROR Empty GetValuesPassword env var")
		os.Exit(1)
	}

	PutValuesUrlPrefix = os.Getenv("PutValuesUrlPrefix")
	if PutValuesUrlPrefix == "" {
		log("ERROR Empty PutValuesUrlPrefix env var")
		os.Exit(1)
	}
	if putvaluesurl, err := url.Parse(PutValuesUrlPrefix); err != nil {
		log("ERROR url.Parse PutValuesUrlPrefix: %v", err)
		os.Exit(1)
	} else {
		PutValuesUrlHost = putvaluesurl.Host
		PutValuesUrlPrefixPath = putvaluesurl.Path
	}

	PutValuesUsername = os.Getenv("PutValuesUsername")
	if PutValuesUsername == "" {
		log("ERROR Empty PutValuesUsername env var")
		os.Exit(1)
	}

	PutValuesPassword = os.Getenv("PutValuesPassword")
	if PutValuesPassword == "" {
		log("ERROR Empty PutValuesPassword env var")
		os.Exit(1)
	}

}

func main() {
	var err error

	if TgWebhookUrl != "" {
		log("TgWebhookUrl=`%s` so setting webhook with telegram to receive updates.", TgWebhookUrl)
		err = TgSetWebhook(TgWebhookUrl, []string{"message", "channel_post"}, TgWebhookToken)
		if err != nil {
			log("TgSetWebhook: %+v", err)
			os.Exit(1)
		}

		http.HandleFunc("/", Webhook)

		go func() {
			for {
				log("http: serving requests on `%s`.", ListenAddr)
				err := http.ListenAndServe(ListenAddr, nil)
				if err != nil {
					log("ERROR http: %+v", err)
				}
				retryinterval := 11 * time.Second
				log("http: retrying in %s.", retryinterval)
				time.Sleep(retryinterval)
			}
		}()
	} else {
		log("TgWebhookUrl is empty so this instance will not receive telegram updates.")
	}

	go func() {
		for {
			err := ServerPackagesUpgrade()
			if err != nil {
				log("ERROR update: %+v", err)
			}
			if DEBUG {
				log("update: sleeping %s.", ServerPackagesUpgradeInterval)
			}
			time.Sleep(ServerPackagesUpgradeInterval)
		}
	}()

	log("start done.")

	for {
		time.Sleep(11 * time.Second)
	}
}

func Webhook(w http.ResponseWriter, r *http.Request) {
	var err error
	if TgWebhookToken != "" && r.Header.Get("X-Telegram-Bot-Api-Secret-Token") != TgWebhookToken {
		log("request with invalid X-Telegram-Bot-Api-Secret-Token header")
		return
	}
	var rbody []byte
	rbody, err = io.ReadAll(r.Body)
	if err != nil {
		log("io.ReadAll r.Body: %s", err)
	}
	log("%s %s %s: %s", r.Method, r.URL, r.Header.Get("Content-Type"), strings.ReplaceAll(string(rbody), NL, ""))
	var rupdate TgUpdate
	err = json.NewDecoder(bytes.NewBuffer(rbody)).Decode(&rupdate)
	if err != nil {
		log("json.Decoder.Decode: %s", err)
	}
	w.WriteHeader(http.StatusOK)

	if rupdate.ChannelPost.MessageId != 0 {
		rupdate.Message = rupdate.ChannelPost
	}

	log("TgUpdate: %#v", rupdate)

	if !slices.Contains(TgChatIds, rupdate.Message.Chat.Id) {
		log("reply to message chat id not valid")
		return
	}
	log("reply to message chat id valid")

	if rupdate.Message.ReplyToMessage.From.Id != TgBotUserId && !slices.Contains(TgChatIds, rupdate.Message.ReplyToMessage.SenderChat.Id) {
		log("reply to message user id not valid")
		return
	}
	log("reply to message user id valid")

	UpdateHashIdSubmatch := UpdateHashIdRe.FindStringSubmatch(rupdate.Message.ReplyToMessage.Text)
	if len(UpdateHashIdSubmatch) == 0 {
		log("reply to message text not valid")
		return
	}
	log("reply to message text valid")

	if !slices.Contains(TgChatIds, rupdate.Message.Chat.Id) {
		log("message chat id not valid")
		return
	}
	log("message chat id valid")

	msgtext := strings.TrimSpace(rupdate.Message.Text)
	if msgtext != "NOW" {
		log("message text not valid")
		return
	}
	log("message text valid")

	if !slices.Contains(TgBossUserIds, rupdate.Message.From.Id) && !slices.Contains(TgChatIds, rupdate.Message.ReplyToMessage.SenderChat.Id) {
		log("message user id not valid")
		err = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*Your request to force update %s is NOT accepted.*"+NL+NL+"Check helmbot TgBossUserIds config value.",
		)
		if err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}
	log("message user id valid")

	log("update hash id submatch: %+v", UpdateHashIdSubmatch)

	UpdateHashId := UpdateHashIdSubmatch[0]
	log("update hash id: %s", UpdateHashId)
	UpdateHelmName := UpdateHashIdSubmatch[1]
	log("update helm name: %s", UpdateHelmName)
	UpdateEnvName := UpdateHashIdSubmatch[2]
	log("update env name: %s", UpdateEnvName)
	UpdateValuesHash := UpdateHashIdSubmatch[3]
	log("update values hash: %s", UpdateValuesHash)

	/*
		if s, err := script.ListFiles(PackagesDir).EachLine(func(l string, o *strings.Builder) { o.WriteString(l + NL) }).Join().String(); err == nil {
			log("%s: %s", PackagesDir, s)
		} else {
			log("ERROR %s: %v", PackagesDir, err)
			return
		}
	*/

	PackageName := fmt.Sprintf("%s-%s", UpdateHelmName, UpdateEnvName)
	PackageDir := fmt.Sprintf("%s/%s/", PackagesDir, PackageName)
	PackageLatestDir := fmt.Sprintf("%s/latest/", PackageDir)
	PackageReportedDir := fmt.Sprintf("%s/reported/", PackageDir)
	PackageDeployedDir := fmt.Sprintf("%s/deployed/", PackageDir)
	if DEBUG {
		log("PackageLatestDir:%s PackageReportedDir:%s PackageDeployedDir:%s",
			PackageLatestDir, PackageReportedDir, PackageDeployedDir,
		)
	}

	deployedvalueshashpath := fmt.Sprintf("%s.%s.%s", UpdateHelmName, UpdateEnvName, ValuesDeployedHashFilenameSuffix)
	var deployedvalueshash string
	if err := GetValuesText(deployedvalueshashpath, &deployedvalueshash); err == nil {
		log("deployed values hash: %s", deployedvalueshash)
		if UpdateValuesHash == deployedvalueshash {
			log("latest and deployed values hashes match")
			err = tglog(
				rupdate.Message.Chat.Id, rupdate.Message.MessageId,
				"*THIS UPDATE IS ALREADY DEPLOYED*",
			)
			if err != nil {
				log("ERROR tglog: %v", err)
			}
			return
		}
	} else {
		log("ERROR `%s` could not be read: %v", deployedvalueshashpath, err)
		err = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*INTERNAL ERROR*",
		)
		if err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}

	reportedvalueshashpath := fmt.Sprintf("%s.%s.%s", UpdateHelmName, UpdateEnvName, ValuesReportedHashFilenameSuffix)
	var reportedvalueshash string
	if err := GetValuesText(reportedvalueshashpath, &reportedvalueshash); err == nil {
		log("reported values hash: %s", reportedvalueshash)
		if UpdateValuesHash == reportedvalueshash {
			log("latest and reported values hashes match")
		} else {
			log("latest and reported values hashes mismatch")
			err = tglog(
				rupdate.Message.Chat.Id, rupdate.Message.MessageId,
				"*THIS IS NOT THE LAST AVAILABLE UPDATE*"+NL+NL+"Only the last available update can be forced.",
			)
			if err != nil {
				log("ERROR tglog: %v", err)
			}
			return
		}
	} else {
		log("ERROR `%s` could not be read: %v", reportedvalueshashpath, err)
		err = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*INTERNAL ERROR*",
		)
		if err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}

	log("all checks passed")

	permithashpath := fmt.Sprintf("%s.%s.%s", UpdateHelmName, UpdateEnvName, PermitHashFilenameSuffix)
	log("creating %s file", permithashpath)

	if err := PutValuesText(permithashpath, UpdateValuesHash); err == nil {
		log("created %s file", permithashpath)
	} else {
		log("%s file could not be written: %v", permithashpath, err)
		err = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*INTERNAL ERROR*",
		)
		if err != nil {
			log("ERROR tglog: %v", err)
		}
		return
	}

	err = tglog(
		rupdate.Message.Chat.Id, rupdate.Message.MessageId,
		"*FORCE UPDATE NOW IS ACCEPTED.*"+
			NL+NL+
			"THIS UPDATE WILL START IN FEW MINUTES."+
			NL+NL+
			"`%s`",
		UpdateHashId,
	)
	if err != nil {
		log("ERROR tglog: %v", err)
	}

	log("finished %s", UpdateHashId)
}

func TgSetWebhook(url string, allowedupdates []string, secrettoken string) error {
	if DEBUG {
		log("TgSetWebhook: url:%s allowedupdates:%s secrettoken:%s", url, allowedupdates, secrettoken)
	}

	type TgSetWebhookRequest struct {
		Url            string   `json:"url"`
		MaxConnections int64    `json:"max_connections"`
		AllowedUpdates []string `json:"allowed_updates"`
		SecretToken    string   `json:"secret_token,omitempty"`
	}

	type TgSetWebhookResponse struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      bool   `json:"result"`
	}

	swreq := TgSetWebhookRequest{
		Url:            url,
		MaxConnections: TgWebhookMaxConnections,
		AllowedUpdates: allowedupdates,
		SecretToken:    secrettoken,
	}
	swreqjs, err := json.Marshal(swreq)
	if err != nil {
		return err
	}
	swreqjsBuffer := bytes.NewBuffer(swreqjs)

	var resp *http.Response
	tgapiurl := fmt.Sprintf("https://api.telegram.org/bot%s/setWebhook", TgToken)
	resp, err = http.Post(
		tgapiurl,
		"application/json",
		swreqjsBuffer,
	)
	if err != nil {
		return fmt.Errorf("apiurl:`%s` apidata:`%s` %v", tgapiurl, swreqjs, err)
	}

	var swresp TgSetWebhookResponse
	var swrespbody []byte
	swrespbody, err = io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("io.ReadAll: %w", err)
	}
	err = json.NewDecoder(bytes.NewBuffer(swrespbody)).Decode(&swresp)
	if err != nil {
		return fmt.Errorf("json.Decoder.Decode: %w", err)
	}
	if !swresp.OK || !swresp.Result {
		return fmt.Errorf("apiurl:`%s` apidata:`%s` api response not ok: %+v", tgapiurl, swreqjs, swresp)
	}

	return nil
}

func ServerPackagesUpgrade() (err error) {
	if DEBUG {
		log("DEBUG ServerPackagesUpgrade hostname:%s ", ServerHostname)
	}

	helmactioncfg := new(helmaction.Configuration)
	err = helmactioncfg.Init(helmcli.New().RESTClientGetter(), "", "", log)
	if err != nil {
		return err
	}

	installedreleases, err := helmaction.NewList(helmactioncfg).Run()
	if err != nil {
		return err
	}

	if DEBUG {
		for _, r := range installedreleases {
			log(
				"DEBUG ServerPackagesUpgrade installed release name:%s version:%s namespace:%s ",
				r.Name, r.Chart.Metadata.Version, r.Namespace,
			)
		}
	}

	var configlocal HelmbotConfig

	configlocalpath := ConfigLocalDir + "/" + ConfigLocalFilename
	err = GetValuesFile(configlocalpath, nil, &configlocal)
	if err != nil {
		log("WARNING ServerPackagesUpgrade GetValuesFile `%s`: %v", configlocalpath, err)
	}

	err = GetValues(ConfigMinioFilename, nil, &Config)
	if err != nil {
		log("WARNING ServerPackagesUpgrade GetValues `%s`: %v", ConfigMinioFilename, err)
	}

	Config.DrLatestYaml = append(Config.DrLatestYaml, configlocal.DrLatestYaml...)
	Config.ServersPackages = append(Config.ServersPackages, configlocal.ServersPackages...)

	if DEBUG {
		log("DEBUG ServerPackagesUpgrade Config: %+v", Config)
	}

	packages := make([]PackageConfig, 0)
	for _, s := range Config.ServersPackages {
		if s.ServerHostname != ServerHostname {
			continue
		}
		if s.AllowedHours != nil {
			s.AllowedHoursList = strings.Split(*s.AllowedHours, " ")
		}
		if s.Timezone == nil || *s.Timezone == "" {
			tzutc := "UTC"
			s.Timezone = &tzutc
			s.TimezoneLocation = time.UTC
		} else {
			s.TimezoneLocation, err = time.LoadLocation(*s.Timezone)
			if err != nil {
				return err
			}
		}
		for _, p := range s.Packages {
			p.Name = fmt.Sprintf("%s-%s", p.HelmName, p.EnvName)

			p.PackageName = fmt.Sprintf("%s-%s", p.HelmName, p.EnvName)

			if p.Namespace == "" {
				p.Namespace = fmt.Sprintf("%s-%s", p.HelmName, p.EnvName)
			}

			p.ServerHostname = &s.ServerHostname

			if p.AllowedHours == nil {
				p.AllowedHours = s.AllowedHours
			}
			if p.AllowedHours != nil {
				p.AllowedHoursList = strings.Split(*p.AllowedHours, " ")
			}

			if p.Timezone == nil {
				p.Timezone = s.Timezone
				p.TimezoneLocation = s.TimezoneLocation
			}

			if p.AlwaysForceNow == nil {
				if s.AlwaysForceNow == nil {
					varfalse := false
					p.AlwaysForceNow = &varfalse
				} else {
					p.AlwaysForceNow = s.AlwaysForceNow
				}
			}

			if p.UpdateDelay == nil {
				p.UpdateDelay = s.UpdateDelay
			}
			if p.TgChatId == nil {
				p.TgChatId = s.TgChatId
			}
			if p.TgMentions == nil {
				p.TgMentions = s.TgMentions
			}
			packages = append(packages, p)
		}
	}

	helmenvsettings := helmcli.New()

	/*
		log("ServerPackagesUpgrade env settings %+v", helmenvsettings)
		if err := os.MkdirAll("/opt/zz/helmbot/helm/cache/", 0750); err != nil {
			return err
		}
		helmenvsettings.RegistryConfig = "/opt/zz/helmbot/helm/registry-config.yaml"
		helmenvsettings.RepositoryConfig = "/opt/zz/helmbot/helm/repository-config.yaml"
		helmenvsettings.RepositoryCache = "/opt/zz/helmbot/helm/cache/"
		log("ServerPackagesUpgrade env settings %+v", helmenvsettings)
	*/

	helmgetterall := helmgetter.All(helmenvsettings)

	kconfig, err := krest.InClusterConfig()
	if err != nil {
		return err
	}
	if DEBUG {
		log("DEBUG ServerPackagesUpgrade kconfig: %+v", kconfig)
	}

	kclientset, err := kubernetes.NewForConfig(kconfig)
	if err != nil {
		return err
	}
	if DEBUG {
		log("DEBUG ServerPackagesUpgrade kclientset: %+v", kclientset)
	}

	log("ServerPackagesUpgrade packages count:%v", len(packages))
	if DEBUG {
		for _, p := range packages {
			log(
				"DEBUG ServerPackagesUpgrade package Name:%s AlwaysForceNow:%v ",
				p.Name, *p.AlwaysForceNow,
			)
		}
	}

	return nil

	// RETURN

	for _, p := range packages {
		timenowhour := fmt.Sprintf("%02d", time.Now().In(p.TimezoneLocation).Hour())

		log("helm. "+"%s AlwaysForceNow:%v AllowedHours:%v Timezone:%s TimeNowHour:%v ", p.Name, *p.AlwaysForceNow, p.AllowedHoursList, *p.Timezone, timenowhour)

		PackageName := fmt.Sprintf("%s-%s", p.HelmName, p.EnvName)
		PackageDir := fmt.Sprintf("%s/%s/", PackagesDir, PackageName)
		PackageLatestDir := fmt.Sprintf("%s/latest/", PackageDir)
		PackageReportedDir := fmt.Sprintf("%s/reported/", PackageDir)
		PackageDeployedDir := fmt.Sprintf("%s/deployed/", PackageDir)

		p.HelmValues = make(map[string]interface{})
		err = GetValues(fmt.Sprintf("%s.values.yaml", p.HelmName), &p.HelmValuesText, p.HelmValues)
		if err != nil {
			return fmt.Errorf("GetValues %s.values.yaml: %w", p.HelmName, err)
		}

		p.HelmEnvValues = make(map[string]interface{})
		err = GetValues(fmt.Sprintf("%s.%s.values.yaml", p.HelmName, p.EnvName), &p.HelmEnvValuesText, p.HelmEnvValues)
		if err != nil {
			return fmt.Errorf("GetValues %s.%s.values.yaml: %w", p.HelmName, p.EnvName, err)
		}

		//log("helm. "+"package config:%+v / "+NL+"// ", p)

		//log("helm. "+"repo address:%s username:%s password:%s", p.HelmRepo.Address, p.HelmRepo.Username, p.HelmRepo.Password)

		chartrepo, err := helmrepo.NewChartRepository(
			&helmrepo.Entry{
				Name:                  fmt.Sprintf("helm.%s.%s", p.HelmName, p.EnvName),
				URL:                   p.HelmRepo.Address,
				Username:              p.HelmRepo.Username,
				Password:              p.HelmRepo.Password,
				InsecureSkipTLSverify: false,
				PassCredentialsAll:    false,
			},
			helmgetterall,
		)
		if err != nil {
			return fmt.Errorf("NewChartRepository %w", err)
		}
		//log("helm. "+"chart repo: %+v", chartrepo)

		indexfilepath, err := chartrepo.DownloadIndexFile()
		if err != nil {
			return fmt.Errorf("DownloadIndexFile %w", err)
		}
		//log("helm. "+"chart repo index file path: %v", indexfilepath)

		idx, err := helmrepo.LoadIndexFile(indexfilepath)
		if err != nil {
			return fmt.Errorf("LoadIndexFile %w", err)
		}

		var chartversion *helmrepo.ChartVersion
		for chartname, chartversions := range idx.Entries {
			if chartname != p.HelmName {
				continue
			}

			if len(chartversions) == 0 {
				return fmt.Errorf("chart repo index: %s: zero chart versions")
			}

			if p.HelmChartVersion != "" {
				for _, v := range chartversions {
					if v.Version == p.HelmChartVersion {
						chartversion = v
					}
				}
			} else {
				sort.Sort(sort.Reverse(chartversions))
				chartversion = chartversions[0]
			}
		}

		if chartversion == nil {
			return fmt.Errorf("helm. "+"chart repo index: helm chart %s: ERROR no chart version found ", p.HelmName)
		}

		if len(chartversion.URLs) < 1 {
			return fmt.Errorf("helm. "+"chart %s: ERROR no chart urls ", p.HelmName)
		}

		charturl, err := helmrepo.ResolveReferenceURL(p.HelmRepo.Address, chartversion.URLs[0])
		if err != nil {
			return err
		}

		//log("helm. "+SPAC+"chart url: %v ", charturl)

		chartdownloader := helmdownloader.ChartDownloader{Getters: helmgetterall}
		chartdownloader.Options = append(chartdownloader.Options, helmgetter.WithUserAgent("helmbot"))
		if p.HelmRepo.Username != "" {
			chartdownloader.Options = append(chartdownloader.Options, helmgetter.WithBasicAuth(p.HelmRepo.Username, p.HelmRepo.Password))
		}

		chartpath, _, err := chartdownloader.DownloadTo(charturl, chartversion.Version, "")
		if err != nil {
			return err
		}

		//log("helm. "+SPAC+"chart downloaded path: %s ", chartpath)

		chartfull, err := helmloader.Load(chartpath)
		if err != nil {
			return err
		}

		if chartfull == nil {
			return fmt.Errorf("chart downloaded from repo is nil")
		}

		//log("helm. "+SPAC+"chart from repo version:%s len(values):%d", chartfull.Metadata.Version, len(chartfull.Values))

		p.ImagesValuesMap = make(map[string]string)

		p.ImagesValuesMap[p.HelmChartVersionKey] = chartversion.Version

		err = drlatestyaml(p.HelmEnvValues, Config.DrLatestYaml, &p.ImagesValuesMap)
		if err != nil {
			return fmt.Errorf("drlatestyaml %s.%s: %w", p.HelmName, p.EnvName, err)
		}

		p.ImagesValuesList, p.ImagesValuesText, err = ImagesValuesMapToList(p.ImagesValuesMap)

		allvaluestext := p.HelmValuesText + p.HelmEnvValuesText + p.ImagesValuesText
		p.ValuesHash = fmt.Sprintf("%x", sha256.Sum256([]byte(allvaluestext)))[:10]

		/*
			installedhelmversion := ""
			for _, r := range installedreleases {
				if r.Name == p.Name && r.Namespace == p.Namespace {
					installedhelmversion = r.Chart.Metadata.Version
				}
			}

			helmversionstatus := "=>"
			if installedhelmversion == chartversion.Version {
				helmversionstatus = "=="
			}
			log("helm. "+SPAC+"chart version: %s %s %s ", installedhelmversion, helmversionstatus, chartversion.Version)
		*/

		//
		// READ DEPLOYED
		//

		DeployedHelmValuesTextPath := fmt.Sprintf("%s/deployed/%s.values.yaml", PackageDir, p.HelmName)
		DeployedHelmValuesTextBytes, err := os.ReadFile(DeployedHelmValuesTextPath)
		if err != nil {
			log("ReadFile %s", err)
		}

		DeployedHelmEnvValuesTextPath := fmt.Sprintf("%s/deployed/%s.%s.values.yaml", PackageDir, p.HelmName, p.EnvName)
		DeployedHelmEnvValuesTextBytes, err := os.ReadFile(DeployedHelmEnvValuesTextPath)
		if err != nil {
			log("ReadFile %s", err)
		}

		DeployedImagesValuesTextPath := fmt.Sprintf("%s/deployed/%s.%s.images.values.yaml", PackageDir, p.HelmName, p.EnvName)
		DeployedImagesValuesTextBytes, err := os.ReadFile(DeployedImagesValuesTextPath)
		if err != nil {
			log("ReadFile %s", err)
		}
		DeployedImagesValuesText := string(DeployedImagesValuesTextBytes)

		ReportedValuesHashPath := fmt.Sprintf("%s.%s.%s", PackageDir, p.HelmName, p.EnvName, ValuesReportedHashFilenameSuffix)
		ReportedValuesHashBytes, err := os.ReadFile(ReportedValuesHashPath)
		if err != nil {
			//log("ReadFile %s", err)
			ReportedValuesHashBytes = []byte{}
		}
		ReportedValuesHash := string(ReportedValuesHashBytes)

		var ReportedPermitHash string
		permithashpath := fmt.Sprintf("%s.%s.%s", p.HelmName, p.EnvName, PermitHashFilenameSuffix)
		err = GetValuesText(permithashpath, &ReportedPermitHash)
		if err != nil {
			log("GetValuesText `%s`: %v", permithashpath, err)
		}

		toreport := false

		if p.HelmValuesText != string(DeployedHelmValuesTextBytes) {
			log("helm. " + SPAC + "HelmValuesText diff ")
			toreport = true
		}

		if p.HelmEnvValuesText != string(DeployedHelmEnvValuesTextBytes) {
			log("helm. " + SPAC + "HelmEnvValuesText diff ")
			toreport = true
		}

		if p.ImagesValuesText != DeployedImagesValuesText {
			log("helm. " + SPAC + "ImagesValuesText diff ")
			toreport = true

			DeployedImagesValuesMap := make(map[string]string)
			d := yaml.NewDecoder(bytes.NewReader(DeployedImagesValuesTextBytes))
			for {
				if err := d.Decode(&DeployedImagesValuesMap); err != nil {
					if err != io.EOF {
						return fmt.Errorf("yaml Decode %w", err)
					}
					break
				}
			}

			//ansibold := func(s string) string { return "\033[1m" + s + "\033[0m" }
			//ansidim := func(s string) string { return "\033[2m" + s + "\033[0m" }
			//ansiitalic := func(s string) string { return "\033[3m" + s + "\033[0m" }
			//ansiunderline := func(s string) string { return "\033[4m" + s + "\033[0m" }
			//ansistrikethru := func(s string) string { return "\033[9m" + s + "\033[0m" }
			//ansired := func(s string) string { return "\033[31m" + s + "\033[0m" }
			//ansibrightred := func(s string) string { return "\033[91m" + s + "\033[0m" }
			imagesvaluesdiff := ""
			iv1, iv2 := DeployedImagesValuesMap, p.ImagesValuesMap
			for name, v1 := range iv1 {
				if v2, ok := iv2[name]; ok {
					if v2 != v1 {
						imagesvaluesdiff += fmt.Sprintf("<> "+"%s: %#v => %#v"+" / ", name, v1, v2)
					}
				} else {
					imagesvaluesdiff += fmt.Sprintf("-- "+"%s: %#v"+" / ", name, v1)
				}
			}
			for name, v2 := range iv2 {
				if _, ok := iv1[name]; !ok {
					imagesvaluesdiff += fmt.Sprintf("++ "+"%s: %#v"+" / ", name, v2)
				}
			}
			log("helm. "+SPAC+"ImagesValues diff: // %s // ", imagesvaluesdiff)

		}

		if p.ValuesHash == ReportedValuesHash {
			log("helm. " + SPAC + "ValuesHash same ")
			toreport = false
		}

		reported := false

		if toreport {

			//
			// WRITE LATEST
			//

			err = os.RemoveAll(PackageLatestDir)
			if err != nil {
				return fmt.Errorf("RemoveAll %s: %w", PackageLatestDir, err)
			}

			err = os.MkdirAll(PackageLatestDir, 0700)
			if err != nil {
				return fmt.Errorf("MkdirAll %s: %w", PackageLatestDir, err)
			}

			HelmValuesTextPath := fmt.Sprintf("%s/%s.values.yaml", PackageLatestDir, p.HelmName)
			err = os.WriteFile(HelmValuesTextPath, []byte(p.HelmValuesText), 0600)
			if err != nil {
				return fmt.Errorf("WriteFile %s: %w", HelmValuesTextPath, err)
			}

			HelmEnvValuesTextPath := fmt.Sprintf("%s/%s.%s.values.yaml", PackageLatestDir, p.HelmName, p.EnvName)
			err = os.WriteFile(HelmEnvValuesTextPath, []byte(p.HelmEnvValuesText), 0600)
			if err != nil {
				return fmt.Errorf("WriteFile %s: %w", HelmEnvValuesTextPath, err)
			}

			ImagesValuesTextPath := fmt.Sprintf("%s/%s.%s.images.values.yaml", PackageLatestDir, p.HelmName, p.EnvName)
			err = os.WriteFile(ImagesValuesTextPath, []byte(p.ImagesValuesText), 0600)
			if err != nil {
				return fmt.Errorf("WriteFile %s: %w", ImagesValuesTextPath, err)
			}

			ValuesHashPath := fmt.Sprintf("%s.%s.%s", p.HelmName, p.EnvName, ValuesLatestHashFilenameSuffix)
			err = os.WriteFile(ValuesHashPath, []byte(p.ValuesHash), 0600)
			if err != nil {
				return fmt.Errorf("WriteFile %s: %w", ValuesHashPath, err)
			}

			log("helm. "+SPAC+"#%s#%s#%s latest ", p.HelmName, p.EnvName, p.ValuesHash)

			//
			// REPORT
			//

			err = os.RemoveAll(PackageReportedDir)
			if err != nil {
				return fmt.Errorf("RemoveAll %s: %w", PackageReportedDir, err)
			}

			err = os.Rename(PackageLatestDir, PackageReportedDir)
			if err != nil {
				return fmt.Errorf("Rename %s %s: %w", PackageLatestDir, PackageReportedDir, err)
			}

			log("helm. "+SPAC+"#%s#%s#%s reported ", p.HelmName, p.EnvName, p.ValuesHash)

			ReportedValuesHash = p.ValuesHash

		}

		if ReportedValuesHash != "" {
			reported = true
		}

		ForceNow := false
		if reported && ReportedPermitHash == ReportedValuesHash {
			ForceNow = true
		}

		todeploy := false

		if p.AlwaysForceNow != nil && *p.AlwaysForceNow {
			todeploy = true
		}

		if slices.Contains(p.AllowedHoursList, timenowhour) {
			todeploy = true
		}

		if ForceNow {
			todeploy = true
		}

		if reported && todeploy {

			//
			// DEPLOY
			//

			err = os.RemoveAll(PackageDeployedDir)
			if err != nil {
				return fmt.Errorf("RemoveAll %s: %w", PackageDeployedDir, err)
			}

			err = os.Rename(PackageReportedDir, PackageDeployedDir)
			if err != nil {
				return fmt.Errorf("Rename %s %s: %w", PackageReportedDir, PackageDeployedDir, err)
			}

			namespaceexists := false
			if kns, err := kclientset.CoreV1().Namespaces().Get(context.TODO(), p.Namespace, kmetav1.GetOptions{}); kerrors.IsNotFound(err) {
				// namespaceexists = false
			} else if err != nil {
				return err
			} else if kns.Name == p.Namespace {
				namespaceexists = true
			}

			if !namespaceexists {
				pnamespace := &kcorev1.Namespace{
					ObjectMeta: kmetav1.ObjectMeta{
						Name: p.Namespace,
					},
				}
				if _, err := kclientset.CoreV1().Namespaces().Create(context.TODO(), pnamespace, kmetav1.CreateOptions{}); err != nil {
					return err
				}
			}

			isinstalled := false
			for _, r := range installedreleases {
				if r.Name == p.Name && r.Namespace == p.Namespace {
					isinstalled = true
				}
			}

			var pkgrelease *helmrelease.Release
			if isinstalled {
				// https://pkg.go.dev/helm.sh/helm/v3@v3.12.3/pkg/action#Upgrade
				helmupgrade := helmaction.NewUpgrade(helmactioncfg)
				helmupgrade.DryRun = true
				helmupgrade.Namespace = p.Namespace

				chart := new(helmchart.Chart)
				values := make(map[string]interface{})
				pkgrelease, err = helmupgrade.Run(
					p.PackageName,
					chart,
					values,
				)
				if err != nil {
					return err
				}
			} else {
				// https://pkg.go.dev/helm.sh/helm/v3@v3.12.3/pkg/action#Install
				helminstall := helmaction.NewInstall(helmactioncfg)
				helminstall.DryRun = true
				helminstall.CreateNamespace = true
				helminstall.Namespace = p.Namespace
				helminstall.ReleaseName = p.PackageName

				chart := new(helmchart.Chart)
				values := make(map[string]interface{})
				pkgrelease, err = helminstall.Run(
					chart,
					values,
				)
				if err != nil {
					return err
				}
			}

			log("helm. "+SPAC+"#%s#%s#%s deployed ", p.HelmName, p.EnvName, p.ValuesHash)
			if pkgrelease == nil {
				log("helm. "+SPAC+"release: %+v ", pkgrelease)
			} else {
				log("helm. "+SPAC+"release info: %s ", pkgrelease.Info.Status)
			}

		}

	}

	return nil
}

func log(msg string, args ...interface{}) {
	var t time.Time
	var tzone string
	if LogUTCTime {
		t = time.Now().UTC()
		tzone = "z"
	} else {
		t = time.Now().Local()
		tzone = LocalZone
	}
	ts := fmt.Sprintf(
		"%03d.%02d%02d.%02d%02d%s",
		t.Year()%1000, t.Month(), t.Day(), t.Hour(), t.Minute(), tzone,
	)
	fmt.Fprintf(os.Stderr, ts+" "+msg+NL, args...)
}

func tglog(chatid int64, replyid int64, msg string, args ...interface{}) error {
	type TgSendMessageRequest struct {
		ChatId              int64  `json:"chat_id"`
		ReplyToMessageId    int64  `json:"reply_to_message_id,omitempty"`
		Text                string `json:"text"`
		ParseMode           string `json:"parse_mode,omitempty"`
		DisableNotification bool   `json:"disable_notification"`
	}

	type TgSendMessageResponse struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      struct {
			MessageId int64 `json:"message_id"`
		} `json:"result"`
	}

	text := fmt.Sprintf(msg, args...)
	text = strings.NewReplacer(
		"(", "\\(",
		")", "\\)",
		"[", "\\[",
		"]", "\\]",
		"{", "\\{",
		"}", "\\}",
		"~", "\\~",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"!", "\\!",
		".", "\\.",
	).Replace(text)

	smreq := TgSendMessageRequest{
		ChatId:              chatid,
		ReplyToMessageId:    replyid,
		Text:                text,
		ParseMode:           TgParseMode,
		DisableNotification: TgDisableNotification,
	}
	smreqjs, err := json.Marshal(smreq)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	smreqjsBuffer := bytes.NewBuffer(smreqjs)

	var resp *http.Response
	tgapiurl := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TgToken)
	resp, err = http.Post(
		tgapiurl,
		"application/json",
		smreqjsBuffer,
	)
	if err != nil {
		return fmt.Errorf("apiurl:`%s` apidata:`%s` %v", tgapiurl, smreqjs, err)
	}

	var smresp TgSendMessageResponse
	err = json.NewDecoder(resp.Body).Decode(&smresp)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	if !smresp.OK {
		return fmt.Errorf("apiurl:`%s` apidata:`%s` api response not ok: %+v", tgapiurl, smreqjs, smresp)
	}

	return nil
}

type TgUpdate struct {
	UpdateId    int64     `json:"update_id"`
	Message     TgMessage `json:"message"`
	ChannelPost TgMessage `json:"channel_post"`
}

type TgMessage struct {
	MessageId      int64  `json:"message_id"`
	From           TgUser `json:"from"`
	SenderChat     TgChat `json:"sender_chat"`
	Chat           TgChat `json:"chat"`
	Date           int64  `json:"date"`
	Text           string `json:"text"`
	ReplyToMessage struct {
		MessageId  int64  `json:"message_id"`
		From       TgUser `json:"from"`
		SenderChat TgChat `json:"sender_chat"`
		Chat       TgChat `json:"chat"`
		Date       int64  `json:"date"`
		Text       string `json:"text"`
	} `json:"reply_to_message"`
}

type TgUser struct {
	Id        int64  `json:"id"`
	IsBot     bool   `json:"is_bot"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
}

type TgChat struct {
	Id    int64  `json:"id"`
	Title string `json:"title"`
	Type  string `json:"type"`
}

// get values file from a minio storage
// https://gist.github.com/gabo89/5e3e316bd4be0fb99369eac512a66537
// https://stackoverflow.com/questions/72047783/how-do-i-download-files-from-a-minio-s3-bucket-using-curl
func GetValuesText(name string, valuestext *string) (err error) {
	r, err := http.NewRequest("GET", GetValuesUrlPrefix+name, nil)
	if err != nil {
		return err
	}
	r.Header.Set("User-Agent", "helmbot")
	hdrcontenttype := "application/octet-stream"
	r.Header.Set("Content-Type", hdrcontenttype)
	r.Header.Set("Host", GetValuesUrlPrefix)
	hdrdate := time.Now().UTC().Format(time.RFC1123Z)
	r.Header.Set("Date", hdrdate)
	hdrauthsig := "GET" + NL + NL + hdrcontenttype + NL + hdrdate + NL + GetValuesUrlPrefixPath + name
	hdrauthsighmac := hmac.New(sha1.New, []byte(GetValuesPassword))
	hdrauthsighmac.Write([]byte(hdrauthsig))
	hdrauthsig = base64.StdEncoding.EncodeToString(hdrauthsighmac.Sum(nil))
	r.Header.Set("Authorization", fmt.Sprintf("AWS %s:%s", GetValuesUsername, hdrauthsig))

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
		log("DEBUG GetValuesText %s: %d length: %s...", name, len(*valuestext), strings.ReplaceAll((*valuestext), NL, " <nl> "))
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("minio server response status: %s", resp.Status)
	}

	return nil
}

func GetValues(name string, valuestext *string, values interface{}) (err error) {
	var tempvaluestext string
	if valuestext == nil {
		valuestext = &tempvaluestext
	}

	err = GetValuesText(name, valuestext)
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

func GetValuesFile(filepath string, valuestext *string, values interface{}) (err error) {
	bb, err := os.ReadFile(filepath)
	if err != nil {
		return err
	}

	if valuestext == nil {
		tempvaluestext := string(bb)
		valuestext = &tempvaluestext
	} else {
		*valuestext = string(bb)
	}

	d := yaml.NewDecoder(strings.NewReader(*valuestext))
	err = d.Decode(values)
	if err != nil {
		return err
	}

	return nil
}

// put values file to a minio storage
// https://gist.github.com/gabo89/5e3e316bd4be0fb99369eac512a66537
// https://stackoverflow.com/questions/72047783/how-do-i-download-files-from-a-minio-s3-bucket-using-curl
func PutValuesText(name string, valuestext string) (err error) {
	r, err := http.NewRequest("PUT", PutValuesUrlPrefix+name, bytes.NewBuffer([]byte(valuestext)))
	if err != nil {
		return err
	}
	r.Header.Set("User-Agent", "helmbot")
	hdrcontenttype := "application/octet-stream"
	r.Header.Set("Content-Type", hdrcontenttype)
	r.Header.Set("Host", PutValuesUrlPrefix)
	hdrdate := time.Now().UTC().Format(time.RFC1123Z)
	r.Header.Set("Date", hdrdate)
	hdrauthsig := "PUT" + NL + NL + hdrcontenttype + NL + hdrdate + NL + PutValuesUrlPrefixPath + name
	hdrauthsighmac := hmac.New(sha1.New, []byte(PutValuesPassword))
	hdrauthsighmac.Write([]byte(hdrauthsig))
	hdrauthsig = base64.StdEncoding.EncodeToString(hdrauthsighmac.Sum(nil))
	r.Header.Set("Authorization", fmt.Sprintf("AWS %s:%s", PutValuesUsername, hdrauthsig))

	if DEBUG {
		log("DEBUG PutValuesText %s: %d length: %s...", name, len(valuestext), strings.ReplaceAll((valuestext), NL, " <nl> "))
	}

	resp, err := http.DefaultClient.Do(r)
	log("DEBUG PutValuesText resp.Status: %s", resp.Status)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("minio server response status: %s", resp.Status)
	}

	return nil
}

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

func drlatestyaml(helmvalues map[string]interface{}, drlatestyamlitems []DrLatestYamlItem, imagesvalues *map[string]string) (err error) {
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

type PackageConfig struct {
	Name        string `yaml:"Name"`
	PackageName string `yaml:"PackageName"`
	Namespace   string `yaml:"Namespace,omitempty"`
	HelmName    string `yaml:"HelmName"`
	EnvName     string `yaml:"EnvName"`

	HelmChartVersion    string `yaml:"HelmChartVersion"`
	HelmChartVersionKey string `yaml:"HelmChartVersionKey"`

	HelmChartLocalFilename string `yaml:"HelmChartLocalFilename"`

	HelmChartAddress string `yaml:"HelmChartAddress"`
	HelmRepo         struct {
		Address  string `yaml:"Address"`
		Username string `yaml:"Username"`
		Password string `yaml:"Password"`
	} `yaml:"HelmRepo"`

	ServerHostname *string `yaml:"ServerHostname,omitempty"`
	TgChatId       *int64  `yaml:"TgChatId,omitempty"`
	TgMentions     *string `yaml:"TgMentions,omitempty"`

	Timezone       *string `yaml:"Timezone,omitempty"`
	AllowedHours   *string `yaml:"AllowedHours,omitempty"`
	AlwaysForceNow *bool   `yaml:"AlwaysForceNow,omitempty"`
	ForceNow       bool    `yaml:"ForceNow"`

	UpdateInterval string  `yaml:"UpdateInterval"`
	UpdateDelay    *string `yaml:"UpdateDelay,omitempty"`

	TimezoneLocation *time.Location
	AllowedHoursList []string

	HelmValuesText string
	HelmValues     map[string]interface{}

	HelmEnvValuesText string
	HelmEnvValues     map[string]interface{}

	ImagesValuesText string
	ImagesValuesList []map[string]string
	ImagesValuesMap  map[string]string

	ValuesHash string `yaml:"ValuesHash"`
}

type ServerConfig struct {
	ServerHostname string  `yaml:"ServerHostname"`
	Timezone       *string `yaml:"Timezone,omitempty"`
	AllowedHours   *string `yaml:"AllowedHours,omitempty"`
	AlwaysForceNow *bool   `yaml:"AlwaysForceNow,omitempty"`
	UpdateDelay    *string `yaml:"UpdateDelay,omitempty"`

	TgChatId   *int64  `yaml:"TgChatId,omitempty"`
	TgMentions *string `yaml:"TgMentions,omitempty"`

	Packages []PackageConfig `yaml:"Packages"`

	AllowedHoursList []string
	TimezoneLocation *time.Location
}

type HelmbotConfig struct {
	DrLatestYaml    []DrLatestYamlItem `yaml:"DrLatestYaml"`
	ServersPackages []ServerConfig     `yaml:"ServersPackages"`
}

func ImagesValuesMapToList(imagesvaluesmap map[string]string) (imagesvalueslist []map[string]string, imagesvaluesyamltext string, err error) {
	imagesvalueslist = make([]map[string]string, 0)
	for k, v := range imagesvaluesmap {
		imagesvalueslist = append(imagesvalueslist, map[string]string{k: v})
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

	imagesvaluestext := new(strings.Builder)
	e := yaml.NewEncoder(imagesvaluestext)
	for _, iv := range imagesvalueslist {
		err := e.Encode(iv)
		if err != nil {
			return nil, "", fmt.Errorf("yaml.Encoder: %w", err)
		}
	}
	imagesvaluesyamltext = imagesvaluestext.String()

	return imagesvalueslist, imagesvaluesyamltext, nil
}
