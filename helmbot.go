/*

GoGet
GoFmt
GoBuildNull

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
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "time/tzdata"

	yaml "gopkg.in/yaml.v3"

	dregistry "github.com/rusenask/docker-registry-client/registry"

	kcorev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	kmetav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubernetes "k8s.io/client-go/kubernetes"
	krest "k8s.io/client-go/rest"

	helmaction "helm.sh/helm/v3/pkg/action"
	helmchart "helm.sh/helm/v3/pkg/chart"
	helmloader "helm.sh/helm/v3/pkg/chart/loader"
	helmchartutil "helm.sh/helm/v3/pkg/chartutil"
	helmcli "helm.sh/helm/v3/pkg/cli"
	helmdownloader "helm.sh/helm/v3/pkg/downloader"
	helmgetter "helm.sh/helm/v3/pkg/getter"
	helmregistry "helm.sh/helm/v3/pkg/registry"
	helmrelease "helm.sh/helm/v3/pkg/release"
	helmrepo "helm.sh/helm/v3/pkg/repo"
)

const (
	SPAC = "    "
	TAB  = "\t"
	NL   = "\n"

	UpdateHashIdReString = "#([-a-z]+)#([-a-z]+)#([a-z0-9]+)$"
)

var (
	DEBUG bool

	LogUTCTime bool

	LocalZone string

	ServerHostname string

	ConfigDir string

	ConfigFilename     string
	HostConfigFilename string

	PackagesUpgradeInterval time.Duration

	ValuesMinioUrl      string
	ValuesMinioUsername string
	ValuesMinioPassword string

	ValuesMinioUrlHost string
	ValuesMinioUrlPath string

	Config   HelmbotConfig
	Packages []PackageConfig

	ListenAddr string

	TgToken                 string
	TgBotUserId             int64
	TgWebhookHost           string
	TgWebhookUrl            string
	TgWebhookToken          string
	TgWebhookMaxConnections int64 = 1
	TgAdminMention          string

	TgChatIds             []int64
	TgBossUserIds         []int64
	TgParseMode           = "MarkdownV2"
	TgDisableNotification = false

	UpdateHashIdRe *regexp.Regexp
)

func init() {
	var err error

	LocalZone = time.Now().Local().Format("-0700")
	if LocalZone == "+0000" {
		LocalZone = "Z"
	}

	UpdateHashIdRe, err = regexp.Compile(UpdateHashIdReString)
	if err != nil {
		log("ERROR regexp %v compile error: %s", UpdateHashIdReString, err)
		os.Exit(1)
	}

	if os.Getenv("DEBUG") != "" {
		DEBUG = true
		log("DEBUG==%v", DEBUG)
	}

	ServerHostname = os.Getenv("ServerHostname")
	if ServerHostname == "" {
		log("ERROR empty ServerHostname env var")
		os.Exit(1)
	}

	ConfigDir = os.Getenv("ConfigDir")
	if ConfigDir == "" {
		log("ERROR empty ConfigDir env var")
		os.Exit(1)
	}
	if !path.IsAbs(ConfigDir) {
		log("ERROR ConfigDir %v must be an absolute path", ConfigDir)
		os.Exit(1)
	}
	if !dirExists(ConfigDir) {
		log("ERROR ConfigDir %v does not exist", ConfigDir)
		os.Exit(1)
	}
	log("DEBUG ConfigDir==%v", ConfigDir)

	ConfigFilename = os.Getenv("ConfigFilename")
	log("DEBUG ConfigFilename==%v", ConfigFilename)
	HostConfigFilename = os.Getenv("HostConfigFilename")
	log("DEBUG HostConfigFilename==%v", HostConfigFilename)

	if v := os.Getenv("PackagesUpgradeInterval"); v != "" {
		if d, err := time.ParseDuration(v); err != nil {
			log("ERROR parse duration PackagesUpgradeInterval==%v: %s", v, err)
			os.Exit(1)
		} else {
			PackagesUpgradeInterval = d
		}
	} else {
		log("ERROR empty PackagesUpgradeInterval env var")
		os.Exit(1)
	}
	log("DEBUG PackagesUpgradeInterval==%v", PackagesUpgradeInterval)

	ValuesMinioUrl = os.Getenv("ValuesMinioUrl")
	if ValuesMinioUrl == "" {
		log("WARNING empty ValuesMinioUrl env var")
	} else if u, err := url.Parse(ValuesMinioUrl); err != nil {
		log("ERROR ValuesMinioUrl `%s` parse error: %s", ValuesMinioUrl, err)
		os.Exit(1)
	} else {
		ValuesMinioUrlHost = u.Host
		ValuesMinioUrlPath = u.Path
	}
	log("DEBUG ValuesMinioUrl==%v", ValuesMinioUrl)

	ValuesMinioUsername = os.Getenv("ValuesMinioUsername")
	if ValuesMinioUsername == "" && ValuesMinioUrlHost != "" {
		log("WARNING empty ValuesMinioUsername env var")
	}

	ValuesMinioPassword = os.Getenv("ValuesMinioPassword")
	if ValuesMinioPassword == "" && ValuesMinioUrlHost != "" {
		log("WARNING empty ValuesMinioPassword env var")
	}

	ListenAddr = os.Getenv("ListenAddr")
	if ListenAddr == "" {
		ListenAddr = ":80"
	}

	TgToken = os.Getenv("TgToken")
	if TgToken == "" {
		log("ERROR empty TgToken env var")
		os.Exit(1)
	}

	if TgToken != "" {
		botuserid := strings.Split(TgToken, ":")[0]
		userid, err := strconv.Atoi(botuserid)
		if err != nil {
			log("ERROR invalid bot user id:`%s`", botuserid)
			os.Exit(1)
		}
		TgBotUserId = int64(userid)
	}
	if TgBotUserId == 0 {
		log("ERROR empty or invalid bot user id")
		os.Exit(1)
	}

	TgAdminMention = os.Getenv("TgAdminMention")
	if TgAdminMention == "" {
		log("WARNING empty TgAdminMention env var")
	}

	TgWebhookHost = os.Getenv("TgWebhookHost")
	if TgWebhookHost == "" {
		log("WARNING empty TgWebhookHost env var")
	}

	TgWebhookUrl = os.Getenv("TgWebhookUrl")
	log("DEBUG TgWebhookUrl==%v", TgWebhookUrl)

	TgWebhookToken = os.Getenv("TgWebhookToken")
	if TgWebhookToken == "" {
		log("WARNING empty TgWebhookToken env var")
	}

	for _, i := range strings.Split(strings.TrimSpace(os.Getenv("TgChatIds")), " ") {
		if i == "" {
			continue
		}
		chatid, err := strconv.Atoi(i)
		if err != nil || chatid == 0 {
			log("WARNING invalid chat id:`%s`", i)
		}
		TgChatIds = append(TgChatIds, int64(chatid))
	}
	if len(TgChatIds) == 0 && TgWebhookUrl != "" {
		log("ERROR empty or invalid TgChatIds env var")
		os.Exit(1)
	}

	for _, i := range strings.Split(strings.TrimSpace(os.Getenv("TgBossUserIds")), " ") {
		if i == "" {
			continue
		}
		userid, err := strconv.Atoi(i)
		if err != nil || userid == 0 {
			log("WARNING invalid user id `%s`", i)
		}
		TgBossUserIds = append(TgBossUserIds, int64(userid))
	}
	if len(TgBossUserIds) == 0 {
		log("ERROR empty or invalid TgBossUserIds env var")
		os.Exit(1)
	}
}

func main() {

	if TgWebhookUrl != "" {
		log("DEBUG TgWebhookUrl==%v so setting webhook with telegram to receive updates.", TgWebhookUrl)
		if err := TgSetWebhook(TgWebhookUrl, []string{"message", "channel_post"}, TgWebhookToken); err != nil {
			log("ERROR TgSetWebhook: %+v", err)
			os.Exit(1)
		}

		http.HandleFunc("/", Webhook)

		go func() {
			for {
				log("DEBUG webhook serving requests on %v.", ListenAddr)
				err := http.ListenAndServe(ListenAddr, nil)
				if err != nil {
					log("ERROR webhook ListenAndServe: %+v", err)
				}
				retryinterval := 11 * time.Second
				log("DEBUG webhook retrying ListenAndServe in %v", retryinterval)
				time.Sleep(retryinterval)
			}
		}()
	} else {
		log("TgWebhookUrl is not set so this instance will not register telegram webhook.")
	}

	if ConfigFilename != "" || HostConfigFilename != "" {
		go func() {
			for {
				t0 := time.Now()

				if err := ServerPackagesUpdate(); err != nil {
					log("ERROR packages: %+v", err)
				}

				if d := time.Now().Sub(t0); d < PackagesUpgradeInterval {
					sleepdur := (PackagesUpgradeInterval - d).Truncate(time.Second)
					log("DEBUG packages sleeping %s", sleepdur)
					time.Sleep(sleepdur)
				}
				log("---")
			}
		}()
	} else {
		log("ConfigFilename nor HostConfigFilename are not set so this instance will not process packages.")
	}

	log("start done.")

	for {
		time.Sleep(11 * time.Second)
	}

}

func Webhook(w http.ResponseWriter, r *http.Request) {
	var err error
	var tgerr error

	if TgWebhookToken != "" && r.Header.Get("X-Telegram-Bot-Api-Secret-Token") != TgWebhookToken {
		log("WARNING webhook request with invalid X-Telegram-Bot-Api-Secret-Token header")
		w.WriteHeader(http.StatusOK)
		return
	}

	var rbody []byte
	rbody, err = io.ReadAll(r.Body)
	if err != nil {
		log("ERROR webhook io.ReadAll r.Body: %v", err)
		w.WriteHeader(http.StatusOK)
		return
	}

	if DEBUG {
		log("DEBUG webhook %s %s %s: %s", r.Method, r.URL, r.Header.Get("Content-Type"), strings.ReplaceAll(string(rbody), NL, " <nl> "))
	}

	w.WriteHeader(http.StatusOK)

	var rupdate TgUpdate
	err = json.NewDecoder(bytes.NewBuffer(rbody)).Decode(&rupdate)
	if err != nil {
		log("ERROR webhook json.Decoder.Decode: %v", err)
		return
	}

	if rupdate.ChannelPost.MessageId != 0 {
		rupdate.Message = rupdate.ChannelPost
	}

	if DEBUG {
		log("DEBUG webhook TgUpdate: %+v", rupdate)
	}

	if !slices.Contains(TgChatIds, rupdate.Message.Chat.Id) {
		log("DEBUG webhook reply to message chat id not valid")
		return
	}
	log("DEBUG webhook reply to message chat id valid")

	if rupdate.Message.ReplyToMessage.From.Id != TgBotUserId && !slices.Contains(TgChatIds, rupdate.Message.ReplyToMessage.SenderChat.Id) {
		log("DEBUG webhook reply to message user id not valid")
		return
	}
	log("DEBUG webhook reply to message user id valid")

	UpdateHashIdSubmatch := UpdateHashIdRe.FindStringSubmatch(rupdate.Message.ReplyToMessage.Text)
	if len(UpdateHashIdSubmatch) == 0 {
		log("DEBUG webhook reply to message text not valid")
		return
	}
	log("DEBUG webhook reply to message text valid")

	if !slices.Contains(TgChatIds, rupdate.Message.Chat.Id) {
		log("DEBUG webhook message chat id not valid")
		return
	}
	log("DEBUG webhook message chat id valid")

	msgtext := strings.TrimSpace(rupdate.Message.Text)
	if msgtext != "NOW" {
		log("DEBUG webhook message text not valid")
		return
	}
	log("DEBUG webhook message text valid")

	if !slices.Contains(TgBossUserIds, rupdate.Message.From.Id) && !slices.Contains(TgChatIds, rupdate.Message.ReplyToMessage.SenderChat.Id) {
		log("DEBUG webhook message user id not valid")
		if _, tgerr = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
			"*Your request to force update %s is NOT accepted.*"+NL+NL+"Check helmbot TgBossUserIds config value.",
		); tgerr != nil {
			log("ERROR webhook tglog: %v", tgerr)
		}
		return
	}
	log("DEBUG webhook message user id valid")

	log("DEBUG webhook update hash id submatch: %+v", UpdateHashIdSubmatch)

	UpdateHashId := UpdateHashIdSubmatch[0]
	log("webhook update hash id: %s", UpdateHashId)
	UpdateChartName := UpdateHashIdSubmatch[1]
	log("webhook update helm name: %s", UpdateChartName)
	UpdateEnvName := UpdateHashIdSubmatch[2]
	log("webhook update env name: %s", UpdateEnvName)
	UpdateValuesHash := UpdateHashIdSubmatch[3]
	log("webhook update values hash: %s", UpdateValuesHash)

	p := PackageConfig{ChartName: UpdateChartName, EnvName: UpdateEnvName}

	var ValuesDeployedHash string
	if err := GetValuesText(p.ValuesDeployedHashFilename(), &ValuesDeployedHash); err != nil {
		log("ERROR webhook %v could not be read: %v", p.ValuesDeployedHashFilename(), err)
		if _, tgerr = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
			"*INTERNAL ERROR*"+NL+
				TgAdminMention,
		); tgerr != nil {
			log("ERROR webhook tglog: %v", tgerr)
		}
		return
	}

	log("webhook deployed values hash: %s", ValuesDeployedHash)
	if UpdateValuesHash == ValuesDeployedHash {
		log("DEBUG webhook latest and deployed values hashes match")
		if _, tgerr = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
			"*THIS UPDATE IS ALREADY DEPLOYED*",
		); tgerr != nil {
			log("ERROR webhook tglog: %v", tgerr)
		}
		return
	}

	var ValuesReportedHash string
	if err := GetValuesText(p.ValuesReportedHashFilename(), &ValuesReportedHash); err != nil {
		log("ERROR webhook %v could not be read: %v", p.ValuesReportedHashFilename(), err)
		if _, tgerr = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
			"*INTERNAL ERROR*"+NL+
				TgAdminMention,
		); tgerr != nil {
			log("ERROR webhook tglog: %v", tgerr)
		}
		return
	}

	log("DEBUG webhook reported values hash: %s", ValuesReportedHash)
	if UpdateValuesHash != ValuesReportedHash {
		log("DEBUG webhook latest and reported values hashes mismatch")
		if _, tgerr = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
			"*THIS IS NOT THE LAST AVAILABLE UPDATE*"+NL+NL+"Only the last available update can be forced.",
		); tgerr != nil {
			log("ERROR webhook tglog: %v", tgerr)
		}
		return
	}
	log("DEBUG webhook latest and reported values hashes match")

	log("DEBUG webhook all checks passed")

	log("DEBUG webhook creating %v file", p.ValuesPermitHashFilename())

	if err := PutValuesText(p.ValuesPermitHashFilename(), UpdateValuesHash); err != nil {
		log("ERROR webhook %v file could not be written: %v", p.ValuesPermitHashFilename(), err)
		if _, tgerr = tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
			"*INTERNAL ERROR*"+NL+
				TgAdminMention,
		); tgerr != nil {
			log("ERROR webhook tglog: %v", tgerr)
		}
		return
	}

	log("DEBUG webhook created %v file", p.ValuesPermitHashFilename())

	if _, tgerr = tglog(
		rupdate.Message.Chat.Id, rupdate.Message.MessageId, 0,
		"*FORCE UPDATE NOW IS ACCEPTED.*"+
			NL+NL+
			"THIS UPDATE WILL START IN FEW MINUTES."+
			NL+NL+
			"`%s`",
		UpdateHashId,
	); tgerr != nil {
		log("ERROR webhook tglog: %v", tgerr)
	}

	log("DEBUG webhook finished %s", UpdateHashId)
}

func ServerPackagesUpdate() (err error) {

	var paused string
	if err := GetValuesTextFile("paused", &paused); err == nil {
		// paused packages update - return with no error
		log("DEBUG packages update paused")
		return nil
	}

	if ConfigFilename != "" {
		if err := GetValues(ConfigFilename, nil, &Config); err != nil {
			log("ERROR packages GetValues: %v", err)
			return err
		}
	}
	if HostConfigFilename != "" {
		if err := GetValues(HostConfigFilename, nil, &Config); err != nil {
			log("ERROR packages GetValues: %v", err)
			return err
		}
	}

	if DEBUG {
		//log("DEBUG packages Config==%+v", Config)
	}

	// KUBERNETES

	krestconfig, err := krest.InClusterConfig()
	if err != nil {
		return err
	}
	if DEBUG {
		//log("DEBUG packages krestconfig==%+v", krestconfig)
	}

	kclientset, err := kubernetes.NewForConfig(krestconfig)
	if err != nil {
		return err
	}

	// HELM

	helmenvsettings := helmcli.New()
	if DEBUG {
		//log("DEBUG packages helmenvsettings==%+v", helmenvsettings)
	}

	helmactioncfg := new(helmaction.Configuration)

	// INSTALLED RELEASES

	if err := helmactioncfg.Init(helmenvsettings.RESTClientGetter(), "", "", log); err != nil {
		return err
	}
	installedreleases, err := helmaction.NewList(helmactioncfg).Run()
	if err != nil {
		return err
	}

	if DEBUG {
		for _, r := range installedreleases {
			log("DEBUG packages Name==%s Namespace==%s Status==%s Revision==%d Version==%s",
				r.Name, r.Namespace, r.Info.Status, r.Version, r.Chart.Metadata.Version,
			)
		}
	}

	Packages, err = ProcessServersPackages(Config.Servers)
	if err != nil {
		log("ERROR packages ProcessServersPackages: %v", err)
		return err
	}

	for _, p := range Packages {

		var pkgpaused string
		if err := GetValuesTextFile(path.Join(p.DeployedDir(), "paused"), &pkgpaused); err == nil {
			// paused package update - skip with no error
			log("DEBUG packages --- Name==%s update paused", p.Name)
			continue
		}

		updatetimestampfilename := path.Join(ConfigDir, p.UpdateTimestampFilename())
		if updatetimestampfilestat, err := os.Stat(updatetimestampfilename); err == nil {
			p.UpdateTimestamp = updatetimestampfilestat.ModTime()
		}

		if d := time.Now().Sub(p.UpdateTimestamp).Truncate(time.Second); d < p.UpdateIntervalDuration {
			log("DEBUG packages --- Name==%s %v until next update", p.Name, p.UpdateIntervalDuration-d)
			continue
		}

		timenowhour := fmt.Sprintf("%02d", time.Now().In(p.TimezoneLocation).Hour())

		log("DEBUG packages --- Name==%s Namespace:%s AlwaysForceNow==%v AllowedHours==%v TimeNowHour==%v UpdateInterval==%v", p.Name, p.Namespace, *p.AlwaysForceNow, p.AllowedHoursList, timenowhour, p.UpdateIntervalDuration)

		if DEBUG {
			//log("DEBUG packages "+SPAC+"config==%#v", p)
			log("DEBUG packages "+SPAC+"repo.address==%#v chartaddress==%#v chartlocalfilename==%#v", p.ChartRepo.Address, p.ChartAddress, p.ChartLocalFilename)
		}

		//
		// READ LATEST VALUES
		//

		err = GetValues(p.GlobalValuesFilename(), &p.GlobalValuesText, p.GlobalValues)
		if err != nil {
			return fmt.Errorf("GetValues %v: %w", p.GlobalValuesFilename(), err)
		}

		err = GetValues(p.ValuesFilename(), &p.ValuesText, p.Values)
		if err != nil {
			return fmt.Errorf("GetValues %v: %w", p.ValuesFilename(), err)
		}

		err = GetValues(p.EnvValuesFilename(), &p.EnvValuesText, p.EnvValues)
		if err != nil {
			return fmt.Errorf("GetValues %v: %w", p.EnvValuesFilename(), err)
		}

		//
		// FETCH CHART INFO
		//

		var chartname, chartversion string
		var chartpath string
		var chartfull *helmchart.Chart

		chartdownloader := helmdownloader.ChartDownloader{Getters: helmgetter.All(helmenvsettings)}
		chartdownloader.Options = append(chartdownloader.Options, helmgetter.WithUserAgent("helmbot"))
		if p.ChartRepo.Address != "" && p.ChartRepo.Username != "" {
			chartdownloader.Options = append(chartdownloader.Options, helmgetter.WithBasicAuth(p.ChartRepo.Username, p.ChartRepo.Password))
		}

		if p.ChartRepo.Address != "" {

			chartrepo, err := helmrepo.NewChartRepository(
				&helmrepo.Entry{
					Name:                  fmt.Sprintf("helm.%s.%s", p.ChartName, p.EnvName),
					URL:                   p.ChartRepo.Address,
					Username:              p.ChartRepo.Username,
					Password:              p.ChartRepo.Password,
					InsecureSkipTLSverify: false,
					PassCredentialsAll:    false,
				},
				helmgetter.All(helmenvsettings),
			)
			if err != nil {
				return fmt.Errorf("NewChartRepository %w", err)
			}
			log("DEBUG packages "+SPAC+"chart repo==%v", chartrepo)

			indexfilepath, err := chartrepo.DownloadIndexFile()
			if err != nil {
				return fmt.Errorf("DownloadIndexFile %w", err)
			}
			log("DEBUG packages "+SPAC+"chart repo index file path %s", indexfilepath)

			idx, err := helmrepo.LoadIndexFile(indexfilepath)
			if err != nil {
				return fmt.Errorf("LoadIndexFile %w", err)
			}

			var repochartversion *helmrepo.ChartVersion
			for repochartname, repochartversions := range idx.Entries {
				if repochartname != p.ChartName {
					continue
				}

				if len(repochartversions) == 0 {
					return fmt.Errorf("chart repo index %v: no chart versions", indexfilepath)
				}

				sort.Sort(sort.Reverse(repochartversions))

				if DEBUG {
					var vv []string
					for _, v := range repochartversions {
						vv = append(vv, v.Version)
					}
					log("DEBUG packages "+SPAC+"repo versions==%+v", vv)
				}

				if p.ChartVersion != "" {
					log("DEBUG packages "+SPAC+"ChartVersion==%#v", p.ChartVersion)
					for _, v := range repochartversions {
						if v.Version == p.ChartVersion {
							log("DEBUG packages "+SPAC+"ChartVersion==%#v found in repo", p.ChartVersion)
							repochartversion = v
						}
					}
				} else {
					repochartversion = repochartversions[0]
				}
			}

			if repochartversion == nil {
				return fmt.Errorf("packages chart %s repo index: no chart version found", p.ChartName)
			}

			chartname = repochartversion.Name
			chartversion = repochartversion.Version
			chartpath = path.Join(ConfigDir, fmt.Sprintf("%s-%s.tgz", chartname, chartversion))
			log("DEBUG packages "+SPAC+"LOCAL chartpath==%v exists==%v", chartpath, fileExists(chartpath))

			if !fileExists(chartpath) {
				if len(repochartversion.URLs) == 0 {
					return fmt.Errorf("packages chart %s: no chart urls", p.ChartName)
				}

				charturl, err := helmrepo.ResolveReferenceURL(p.ChartRepo.Address, repochartversion.URLs[0])
				if err != nil {
					return err
				}
				if chartpath, _, err = chartdownloader.DownloadTo(charturl, chartversion, ConfigDir); err != nil {
					return err
				}
			}

		} else if p.ChartAddress != "" {

			chartaddress := p.ChartAddress
			chartaddress = strings.TrimPrefix(chartaddress, "https://")
			chartaddress = strings.TrimPrefix(chartaddress, "oci://")

			hrclient, err := helmregistry.NewClient(helmregistry.ClientOptDebug(true))
			if err != nil {
				return fmt.Errorf("helmregistry.NewClient: %v", err)
			}

			tags, err := hrclient.Tags(chartaddress)
			if err != nil {
				return fmt.Errorf("hrclient.Tags: %v", err)
			}

			if len(tags) == 0 {
				return fmt.Errorf("ChartAddress==%v empty tags list", p.ChartAddress, err)
			}

			log("DEBUG packages "+SPAC+"tags==%+v", tags)

			chartversion = tags[0]

			if u, err := url.Parse(p.ChartAddress); err != nil {
				return fmt.Errorf("parse ChartAddress==%v: %v", p.ChartAddress, err)
			} else {
				chartname = path.Base(u.Path)
				chartpath = path.Join(ConfigDir, fmt.Sprintf("%s-%s.tgz", chartname, chartversion))
				log("DEBUG packages "+SPAC+"LOCAL chartpath==%v exists==%v", chartpath, fileExists(chartpath))
			}

			if !fileExists(chartpath) {
				if chartpath, _, err = chartdownloader.DownloadTo(p.ChartAddress, chartversion, ConfigDir); err != nil {
					return err
				}
			}

		} else if p.ChartLocalFilename != "" {

			if !strings.HasSuffix(p.ChartLocalFilename, ".tgz") {
				return fmt.Errorf("ChartLocalFilename==%v is not a .tgz file", p.ChartLocalFilename)
			}

			if mm, err := filepath.Glob(path.Join(ConfigDir, p.ChartLocalFilename)); err != nil {
				return fmt.Errorf("Glob ConfigDir==%v ChartLocalFilename==%v: %s", ConfigDir, p.ChartLocalFilename, err)
			} else if len(mm) == 0 {
				return fmt.Errorf("Glob ConfigDir==%v ChartLocalFilename==%v files not found", ConfigDir, p.ChartLocalFilename)
			} else {
				sort.Sort(sort.Reverse(sort.StringSlice(mm)))
				chartpath = mm[0]
			}

		} else {

			return fmt.Errorf("no ChartRepoAddress, ChartAddress, ChartLocalFilename")

		}

		log("DEBUG packages "+SPAC+"chartpath==%v", chartpath)

		// https://pkg.go.dev/helm.sh/helm/v3/pkg/chart/loader#Load
		chartfull, err = helmloader.Load(chartpath)
		if err != nil {
			return fmt.Errorf("helmloader.Load %v: %w", chartpath, err)
		} else if chartfull == nil {
			return fmt.Errorf("loaded chart is nil")
		}

		// https://pkg.go.dev/helm.sh/helm/v3@v3.16.3/pkg/chart#Metadata
		chartversion = chartfull.Metadata.Version
		log("DEBUG packages "+SPAC+"chart version==%v", chartversion)

		//
		// FILL IMAGES VALUES
		//

		p.ImagesValues[p.ChartVersionKey] = chartversion

		drlatestyamlhelmvalues := make(map[string]interface{})
		for _, m := range []map[string]interface{}{chartfull.Values, p.Values, p.EnvValues} {
			for k, v := range m {
				drlatestyamlhelmvalues[k] = v
			}
		}
		err = drlatestyaml(drlatestyamlhelmvalues, Config.DrLatestYaml, &p.ImagesValues)
		if err != nil {
			return fmt.Errorf("drlatestyaml %s: %w", p.Name, err)
		}

		p.ImagesValuesList, p.ImagesValuesText, err = ImagesValuesToList(p.ImagesValues)

		log("DEBUG packages "+SPAC+"ImagesValues==%#v", p.ImagesValues)

		//
		// LATEST UPDATE TIMESTAMP
		//

		timenow := time.Now()
		if err := os.Chtimes(updatetimestampfilename, timenow, timenow); os.IsNotExist(err) {
			if f, err := os.Create(updatetimestampfilename); err == nil {
				f.Close()
			} else {
				log("ERROR packages "+SPAC+"create timestamp file: %v", err)
			}
		}

		//
		// WRITE LATEST VALUES HASH
		//

		allvaluestext := p.GlobalValuesText + p.ValuesText + p.EnvValuesText + p.ImagesValuesText
		p.ValuesHash = fmt.Sprintf("%x", sha256.Sum256([]byte(allvaluestext)))[:10]

		if err := PutValuesText(p.ValuesLatestHashFilename(), p.ValuesHash); err != nil {
			return fmt.Errorf("PutValuesText: %w", err)
		}

		//
		// READ DEPLOYED HASH
		//

		var ValuesDeployedHash string
		if err := GetValuesText(p.ValuesDeployedHashFilename(), &ValuesDeployedHash); err != nil {
			log("ERROR packages "+SPAC+"GetValuesText: %s", err)
		}

		//
		// COMPARE LATEST HASH VS DEPLOYED HASH
		//

		if p.ValuesHash == ValuesDeployedHash {

			log("DEBUG packages " + SPAC + "ValuesHash==ValuesDeployedHash")
			time.Sleep(1 * time.Second)
			continue

		}

		//
		// READ DEPLOYED VALUES
		//

		var DeployedGlobalValuesText string
		if err := GetValuesTextFile(path.Join(p.DeployedDir(), p.GlobalValuesFilename()), &DeployedGlobalValuesText); err != nil {
			log("ERROR packages "+SPAC+"GetValuesTextFile: %s", err)
		}

		var DeployedValuesText string
		if err := GetValuesTextFile(path.Join(p.DeployedDir(), p.ValuesFilename()), &DeployedValuesText); err != nil {
			log("ERROR packages "+SPAC+"GetValuesTextFile: %s", err)
		}

		var DeployedEnvValuesText string
		if err := GetValuesTextFile(path.Join(p.DeployedDir(), p.EnvValuesFilename()), &DeployedEnvValuesText); err != nil {
			log("ERROR packages "+SPAC+"GetValuesTextFile: %s", err)
		}

		var DeployedImagesValuesText string
		if err := GetValuesTextFile(path.Join(p.DeployedDir(), p.ImagesValuesFilename()), &DeployedImagesValuesText); err != nil {
			log("ERROR packages "+SPAC+"GetValuesTextFile: %s", err)
		}

		//
		// COMPARE LATEST VS DEPLOYED
		//

		globalvaluesdiff := false
		valuesdiff := false
		envvaluesdiff := false
		imagesvaluesdiff := ""

		if p.GlobalValuesText != DeployedGlobalValuesText {
			globalvaluesdiff = true
		}

		if p.ValuesText != DeployedValuesText {
			valuesdiff = true
		}

		if p.EnvValuesText != DeployedEnvValuesText {
			envvaluesdiff = true
		}

		if p.ImagesValuesText != DeployedImagesValuesText {

			DeployedImagesValuesMap := make(map[string]string)
			yd := yaml.NewDecoder(strings.NewReader(DeployedImagesValuesText))
			for {
				if err := yd.Decode(&DeployedImagesValuesMap); err != nil {
					if err != io.EOF {
						return fmt.Errorf("yaml Decode %w", err)
					}
					break
				}
			}

			iv1, iv2 := DeployedImagesValuesMap, p.ImagesValues
			for name, v1 := range iv1 {
				if v2, ok := iv2[name]; ok {
					if v2 != v1 {
						imagesvaluesdiff += fmt.Sprintf("%s: %#v=>%#v "+NL, name, v1, v2)
					}
				} else {
					imagesvaluesdiff += fmt.Sprintf("-- %s: %#v "+NL, name, v1)
				}
			}
			for name, v2 := range iv2 {
				if _, ok := iv1[name]; !ok {
					imagesvaluesdiff += fmt.Sprintf("++ %s: %#v "+NL, name, v2)
				}
			}

			log("DEBUG packages "+SPAC+"ImagesValues diff: "+NL+"%v", imagesvaluesdiff)

		}

		//
		// READ REPORTED HASH
		//

		var ValuesReportedHash string
		if err := GetValuesText(p.ValuesReportedHashFilename(), &ValuesReportedHash); err != nil {
			log("ERROR packages "+SPAC+"GetValuesText: %s", err)
		}

		if p.ValuesHash != ValuesReportedHash {

			//
			// WRITE REPORTED HASH
			//

			if err := PutValuesText(p.ValuesReportedHashFilename(), p.ValuesHash); err != nil {
				return fmt.Errorf("PutValuesText: %w", err)
			}

		}

		//
		// READ PERMIT HASH
		//

		var PermitHash string
		if err := GetValuesText(p.ValuesPermitHashFilename(), &PermitHash); err != nil {
			log("ERROR packages "+SPAC+"GetValuesText: %s", err)
		}

		log("DEBUG packages "+SPAC+"ValuesHash==%v ValuesReportedHash==%v ValuesDeployedHash==%v PermitHash==%v ", p.ValuesHash, ValuesReportedHash, ValuesDeployedHash, PermitHash)

		//
		// CHECK IF DEPLOY IS ALLOWED NOW
		//

		deploynow := false

		if p.AlwaysForceNow != nil && *p.AlwaysForceNow {
			deploynow = true
		}
		if slices.Contains(p.AllowedHoursList, timenowhour) {
			deploynow = true
		}
		if PermitHash == p.ValuesHash {
			deploynow = true
		}

		//
		// PREPARE TELEGRAM MESSAGE
		//

		var tgmsg string
		var tgmsgid int64
		var tgerr error

		tgmsg = fmt.Sprintf("*%s %s UPDATE*", strings.ToUpper(p.ChartName), strings.ToUpper(p.EnvName)) + NL + NL
		if globalvaluesdiff {
			tgmsg += fmt.Sprintf("`%s` changed", p.GlobalValuesFilename()) + NL + NL
		}
		if valuesdiff {
			tgmsg += fmt.Sprintf("`%s` changed", p.ValuesFilename()) + NL + NL
		}
		if envvaluesdiff {
			tgmsg += fmt.Sprintf("`%s` changed", p.EnvValuesFilename()) + NL + NL
		}
		if imagesvaluesdiff != "" {
			tgmsg += fmt.Sprintf("`%s` diff:"+NL+"```"+NL+"%s"+NL+"```", p.ImagesValuesFilename(), imagesvaluesdiff) + NL + NL
		}

		if !deploynow {

			if p.ValuesHash != ValuesReportedHash {

				tgmsg += "*NOT UPDATING NOW*; update will start *in the next allowed time window*" + NL + NL
				tgmsg += "TO FORCE START THIS UPDATE NOW REPLY TO THIS MESSAGE WITH TEXT \"`NOW`\" (UPPERCASE)" + NL + NL
				if tgmsgid, tgerr = tglog(TgBossUserIds[0], 0, 0, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
					log("ERROR packages tglog: %v", tgerr)
				}

			}

			time.Sleep(1 * time.Second)
			continue

		}

		if p.UpdateDelayDuration > 0 {

			tgmsg += fmt.Sprintf("*STARTING IN %v*", p.UpdateDelayDuration) + NL + NL

			if tgmsgid, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
				log("ERROR packages tglog: %v", tgerr)
			}

			log("DEBUG packages "+SPAC+"sleeping %v", p.UpdateDelayDuration)
			time.Sleep(p.UpdateDelayDuration)

		}

		//
		// DEPLOY
		//

		tgmsg += fmt.Sprintf("*STARTED*") + NL + NL

		if tgmsgid, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
			log("ERROR packages tglog: %v", tgerr)
		}

		// PREPARE VALUES

		values := make(map[string]interface{})
		helmchartutil.MergeTables(values, p.ImagesValues)
		helmchartutil.MergeTables(values, p.EnvValues)
		helmchartutil.MergeTables(values, p.Values)
		helmchartutil.MergeTables(values, p.GlobalValues)
		helmchartutil.MergeTables(values, chartfull.Values)

		log("DEBUG packages "+SPAC+"values==%+v", values)

		if err := helmactioncfg.Init(helmenvsettings.RESTClientGetter(), p.Namespace, "", log); err != nil {
			tgmsg += fmt.Sprintf("*INTERNAL ERROR*") + NL + NL
			if tgmsgid, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
				log("ERROR packages tglog: %v", tgerr)
			}
			return err
		}

		namespaceexists := false
		if kns, err := kclientset.CoreV1().Namespaces().Get(context.TODO(), p.Namespace, kmetav1.GetOptions{}); kerrors.IsNotFound(err) {
			// namespaceexists == false
		} else if err != nil {
			log("ERROR packages Namespaces.Get: %v", err)
			tgmsg += fmt.Sprintf("*INTERNAL ERROR*") + NL + NL
			if tgmsgid, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
				log("ERROR packages tglog: %v", tgerr)
			}
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
				log("ERROR packages Namespaces.Create: %v", err)
				tgmsg += fmt.Sprintf("*INTERNAL ERROR*") + NL + NL
				if tgmsgid, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
					log("ERROR packages tglog: %v", tgerr)
				}
				return err
			}
		}

		isinstalled := false
		for _, r := range installedreleases {
			if r.Name == p.Name && r.Namespace == p.Namespace {
				isinstalled = true
			}
		}

		var release *helmrelease.Release

		if isinstalled {

			// https://pkg.go.dev/helm.sh/helm/v3/pkg/action#Upgrade
			helmupgrade := helmaction.NewUpgrade(helmactioncfg)
			helmupgrade.DryRun = *p.DryRun
			helmupgrade.Namespace = p.Namespace

			release, err = helmupgrade.Run(
				p.Name,
				chartfull,
				values,
			)
			if err != nil {

				log("ERROR packages helmupgrade.Run: %v", err)

				tgmsg += fmt.Sprintf("*ERROR*:"+NL+"```"+NL+"%v"+NL+"```", err)

				if _, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
					log("ERROR packages tglog: %v", tgerr)
				}

				return err

			}

		} else {

			// https://pkg.go.dev/helm.sh/helm/v3/pkg/action#Install
			helminstall := helmaction.NewInstall(helmactioncfg)
			helminstall.DryRun = *p.DryRun
			helminstall.CreateNamespace = true
			helminstall.Namespace = p.Namespace
			helminstall.ReleaseName = p.Name

			release, err = helminstall.Run(
				chartfull,
				values,
			)
			if err != nil {

				log("ERROR packages helminstall.Run: %v", err)

				tgmsg += fmt.Sprintf("*ERROR*:"+NL+"```"+NL+"%v"+NL+"```", err)

				if _, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
					log("ERROR packages tglog: %v", tgerr)
				}

				return err

			}

		}

		log("DEBUG packages "+SPAC+"release Name==%v Namespace==%v Info.Status==%v Revision==%v HashId==%v", release.Name, release.Namespace, release.Info.Status, release.Version, p.HashId())

		tgmsg += fmt.Sprintf(
			"```"+NL+
				"NAME: %v"+NL+
				"NAMESPACE: %v"+NL+
				"STATUS: %v"+NL+
				"REVISION: %v"+NL+
				"```",
			release.Name,
			release.Namespace,
			release.Info.Status,
			release.Version,
		) + NL + NL
		if release.Info.Notes != "" {
			tgmsg += fmt.Sprintf(
				"```"+NL+
					"%s"+NL+
					"```",
				strings.TrimSpace(release.Info.Notes),
			) + NL + NL
		}
		tgmsg += fmt.Sprintf("*%s %s UPDATE FINISHED*", strings.ToUpper(p.ChartName), strings.ToUpper(p.EnvName)) + NL + NL

		if tgmsgid, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
			log("ERROR packages tglog: %v", tgerr)
		}

		//
		// WRITE DEPLOYED VALUES
		//

		if err := p.WriteDeployedValues(); err != nil {
			log("ERROR packages "+SPAC+"WriteDeployedValues: %v", err)
			tgmsg += fmt.Sprintf("*INTERNAL ERROR*") + NL + NL
			if tgmsgid, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
				log("ERROR packages tglog: %v", tgerr)
			}
			return err
		}

		if err := PutValuesText(p.ValuesDeployedHashFilename(), p.ValuesHash); err != nil {
			tgmsg += fmt.Sprintf("*INTERNAL ERROR*") + NL + NL
			if tgmsgid, tgerr = tglog(TgBossUserIds[0], 0, tgmsgid, tgmsg+fmt.Sprintf("`%s`", p.HashId())); tgerr != nil {
				log("ERROR packages tglog: %v", tgerr)
			}
			return fmt.Errorf("PutValuesText: %w", err)
		}

		// TODO remove p.ValuesPermitHashFilename()

		//
		// DEPLOY FINISHED
		//

		time.Sleep(1 * time.Second)
		continue

	}

	return nil

}

func ProcessServersPackages(servers []ServerConfig) (packages []PackageConfig, err error) {

	for _, s := range servers {

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
				return nil, err
			}
		}

		if s.UpdateInterval != nil && *s.UpdateInterval != "" {
			s.UpdateIntervalDuration, err = time.ParseDuration(*s.UpdateInterval)
			if err != nil {
				return nil, err
			}
		}

		if s.UpdateDelay != nil && *s.UpdateDelay != "" {
			s.UpdateDelayDuration, err = time.ParseDuration(*s.UpdateDelay)
			if err != nil {
				return nil, err
			}
		}

		if s.DryRun == nil {
			varfalse := false
			s.DryRun = &varfalse
		}

		for _, p := range s.Packages {

			if p.ChartName == "" {
				return nil, fmt.Errorf("package ChartName is empty")
			}

			if p.EnvName == "" {
				p.EnvName = s.EnvName
			}
			if p.EnvName == "" {
				return nil, fmt.Errorf("package EnvName is empty")
			}

			p.Name = fmt.Sprintf("%s-%s", p.ChartName, p.EnvName)

			if p.Namespace == "" {
				p.Namespace = fmt.Sprintf("%s-%s", p.ChartName, p.EnvName)
			}

			p.ServerHostname = &s.ServerHostname

			if p.AllowedHours == nil {
				p.AllowedHours = s.AllowedHours
				p.AllowedHoursList = s.AllowedHoursList
			} else {
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

			if p.UpdateInterval == nil {
				p.UpdateInterval = s.UpdateInterval
				p.UpdateIntervalDuration = s.UpdateIntervalDuration
			} else {
				p.UpdateIntervalDuration, err = time.ParseDuration(*p.UpdateInterval)
				if err != nil {
					return nil, err
				}
			}

			if p.UpdateDelay == nil {
				p.UpdateDelay = s.UpdateDelay
				p.UpdateDelayDuration = s.UpdateDelayDuration
			} else {
				p.UpdateDelayDuration, err = time.ParseDuration(*p.UpdateDelay)
				if err != nil {
					return nil, err
				}
			}

			if p.ChartVersionKey == "" {
				return nil, fmt.Errorf("package ChartVersionKey is empty")
				// TODO prometheus-node-exporter => PrometheusNodeExporter
				//p.ChartVersionKey = "HelmChartVersion" + textcases.Title(textlanguage.English, textcases.NoLower).String(p.ChartName)
			}

			if p.TgChatId == nil {
				p.TgChatId = s.TgChatId
			}
			if p.TgMentions == nil {
				p.TgMentions = s.TgMentions
			}

			if p.DryRun == nil {
				p.DryRun = s.DryRun
			}

			p.GlobalValues = make(map[string]interface{})
			p.Values = make(map[string]interface{})
			p.EnvValues = make(map[string]interface{})
			p.ImagesValues = make(map[string]interface{})

			packages = append(packages, p)

		}

	}

	return packages, nil
}

func GetValuesText(name string, valuestext *string) (err error) {
	if ValuesMinioUrlHost != "" {
		return GetValuesTextMinio(name, valuestext)
	}
	return GetValuesTextFile(name, valuestext)
}

func GetValues(name string, valuestext *string, values interface{}) (err error) {
	if ValuesMinioUrlHost != "" {
		return GetValuesMinio(name, valuestext, values)
	}
	return GetValuesFile(name, valuestext, values)
}

func PutValuesText(name string, valuestext string) (err error) {
	if ValuesMinioUrlHost != "" {
		return PutValuesTextMinio(name, valuestext)
	}
	return PutValuesTextFile(name, valuestext)
}

func GetValuesTextFile(name string, valuestext *string) (err error) {
	filepath := path.Join(ConfigDir, name)

	bb, err := os.ReadFile(filepath)
	if err != nil {
		//log("ERROR ReadFile %v: %v", filepath, err)
		return err
	}

	if valuestext == nil {
		tempvaluestext := string(bb)
		valuestext = &tempvaluestext
	} else {
		*valuestext = string(bb)
	}

	return nil
}

func GetValuesFile(name string, valuestext *string, values interface{}) (err error) {
	if valuestext == nil {
		var valuestext1 string
		valuestext = &valuestext1
	}

	err = GetValuesTextFile(name, valuestext)
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

func PutValuesTextFile(name string, valuestext string) (err error) {
	filepath := path.Join(ConfigDir, name)

	err = os.WriteFile(filepath, []byte(valuestext), 0644)
	if err != nil {
		//log("ERROR WriteFile %v: %v", filepath, err)
		return err
	}
	return nil
}

type PackageConfig struct {
	Name string `yaml:"Name"`

	ChartName string `yaml:"ChartName"`
	EnvName   string `yaml:"EnvName"`

	Namespace string `yaml:"Namespace,omitempty"`

	ChartVersion    string `yaml:"ChartVersion"`
	ChartVersionKey string `yaml:"ChartVersionKey"`

	ChartLocalFilename string `yaml:"ChartLocalFilename"`

	ChartAddress string `yaml:"ChartAddress"`

	ChartRepo struct {
		Address  string `yaml:"Address"`
		Username string `yaml:"Username"`
		Password string `yaml:"Password"`
	} `yaml:"ChartRepo"`

	ServerHostname *string `yaml:"ServerHostname,omitempty"`

	TgChatId   *int64  `yaml:"TgChatId,omitempty"`
	TgMentions *string `yaml:"TgMentions,omitempty"`

	AlwaysForceNow *bool `yaml:"AlwaysForceNow,omitempty"`
	ForceNow       bool  `yaml:"ForceNow"`

	UpdateInterval *string `yaml:"UpdateInterval,omitempty"`
	UpdateDelay    *string `yaml:"UpdateDelay,omitempty"`

	Timezone     *string `yaml:"Timezone,omitempty"`
	AllowedHours *string `yaml:"AllowedHours,omitempty"`

	UpdateIntervalDuration time.Duration
	UpdateDelayDuration    time.Duration
	UpdateTimestamp        time.Time

	TimezoneLocation *time.Location
	AllowedHoursList []string

	GlobalValuesText string
	ValuesText       string
	EnvValuesText    string
	ImagesValuesText string

	GlobalValues     map[string]interface{}
	Values           map[string]interface{}
	EnvValues        map[string]interface{}
	ImagesValuesList []map[string]interface{}
	ImagesValues     map[string]interface{}

	ValuesHash string `yaml:"ValuesHash"`

	DryRun *bool `yaml:"DryRun,omitempty"`
}

func (p *PackageConfig) DeployedDir() string {
	return p.Name
}

func (p *PackageConfig) GlobalValuesFilename() string {
	return "global.values.yaml"
}
func (p *PackageConfig) ValuesFilename() string {
	return fmt.Sprintf("%s.values.yaml", p.ChartName)
}
func (p *PackageConfig) EnvValuesFilename() string {
	return fmt.Sprintf("%s.%s.values.yaml", p.ChartName, p.EnvName)
}
func (p *PackageConfig) ImagesValuesFilename() string {
	return fmt.Sprintf("%s.%s.images.values.yaml", p.ChartName, p.EnvName)
}

func (p *PackageConfig) ValuesLatestHashFilename() string {
	return fmt.Sprintf("%s.%s.values.latest.hash.text", p.ChartName, p.EnvName)
}
func (p *PackageConfig) ValuesReportedHashFilename() string {
	return fmt.Sprintf("%s.%s.values.reported.hash.text", p.ChartName, p.EnvName)
}
func (p *PackageConfig) ValuesDeployedHashFilename() string {
	return fmt.Sprintf("%s.%s.values.deployed.hash.text", p.ChartName, p.EnvName)
}
func (p *PackageConfig) ValuesPermitHashFilename() string {
	return fmt.Sprintf("%s.%s.values.permit.hash.text", p.ChartName, p.EnvName)
}

func (p *PackageConfig) UpdateTimestampFilename() string {
	return fmt.Sprintf("%s.%s.update.timestamp", p.ChartName, p.EnvName)
}

func (p *PackageConfig) HashId() string {
	return fmt.Sprintf("#%s#%s#%s", p.ChartName, p.EnvName, p.ValuesHash)
}

func (p *PackageConfig) WriteDeployedValues() error {

	if err := os.RemoveAll(path.Join(ConfigDir, p.DeployedDir())); err != nil {
		return fmt.Errorf("RemoveAll: %w", err)
	}
	if err := os.MkdirAll(path.Join(ConfigDir, p.DeployedDir()), 0700); err != nil {
		return fmt.Errorf("MkdirAll: %w", err)
	}

	if err := PutValuesTextFile(path.Join(p.DeployedDir(), p.GlobalValuesFilename()), p.GlobalValuesText); err != nil {
		return fmt.Errorf("PutValuesTextFile: %w", err)
	}
	if err := PutValuesTextFile(path.Join(p.DeployedDir(), p.ValuesFilename()), p.ValuesText); err != nil {
		return fmt.Errorf("PutValuesTextFile: %w", err)
	}
	if err := PutValuesTextFile(path.Join(p.DeployedDir(), p.EnvValuesFilename()), p.EnvValuesText); err != nil {
		return fmt.Errorf("PutValuesTextFile: %w", err)
	}
	if err := PutValuesTextFile(path.Join(p.DeployedDir(), p.ImagesValuesFilename()), p.ImagesValuesText); err != nil {
		return fmt.Errorf("PutValuesTextFile: %w", err)
	}

	return nil
}

type ServerConfig struct {
	ServerHostname string `yaml:"ServerHostname"`

	EnvName string `yaml:"EnvName"`

	AlwaysForceNow *bool `yaml:"AlwaysForceNow,omitempty"`

	UpdateInterval *string `yaml:"UpdateInterval,omitempty"`
	UpdateDelay    *string `yaml:"UpdateDelay,omitempty"`

	UpdateIntervalDuration time.Duration
	UpdateDelayDuration    time.Duration

	TgChatId   *int64  `yaml:"TgChatId,omitempty"`
	TgMentions *string `yaml:"TgMentions,omitempty"`

	Packages []PackageConfig `yaml:"Packages"`

	Timezone     *string `yaml:"Timezone,omitempty"`
	AllowedHours *string `yaml:"AllowedHours,omitempty"`

	TimezoneLocation *time.Location
	AllowedHoursList []string

	DryRun *bool `yaml:"DryRun,omitempty"`
}

type HelmbotConfig struct {
	DrLatestYaml []DrLatestYamlItem `yaml:"DrLatestYaml"`
	Servers      []ServerConfig     `yaml:"Servers"`
}

func log(msg string, args ...interface{}) {
	t := time.Now()
	var tzone string
	if LogUTCTime {
		t = t.UTC()
		tzone = "Z"
	} else {
		t = t.Local()
		tzone = LocalZone
	}
	ts := fmt.Sprintf(
		"%d:%02d%02d:%02d%02d%s",
		t.Year()%1000, t.Month(), t.Day(), t.Hour(), t.Minute(), tzone,
	)
	fmt.Fprintf(os.Stderr, ts+" "+msg+NL, args...)
}

func dirExists(path string) bool {
	s, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && s.IsDir()
}

func fileExists(path string) bool {
	s, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && s.Mode().IsRegular()
}

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
	if req, err := MinioNewRequest(http.MethodGet, name, nil); err != nil {
		return err
	} else if resp, err := http.DefaultClient.Do(req); err != nil {
		return err
	} else if resp.StatusCode != 200 {
		return fmt.Errorf("minio server response status %s", resp.Status)
	} else if bb, err := ioutil.ReadAll(resp.Body); err != nil {
		return err
	} else {
		*valuestext = string(bb)
	}

	if DEBUG {
		log("DEBUG GetValuesTextMinio %s [len %d]: %s", name, len(*valuestext), strings.ReplaceAll(*valuestext, NL, " <nl> "))
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
		log("DEBUG PutValuesTextMinio %s [len==%d]: %s", name, len(valuestext), strings.ReplaceAll((valuestext), NL, " <nl> "))
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
		for _, e := range drlatestyamlitems {
			if strings.HasPrefix(helmvalueskey, e.KeyPrefix) {

				imagename := helmvalueskey
				imagenamereplace := e.KeyPrefixReplace + strings.TrimPrefix(imagename, e.KeyPrefix)

				if v, ok := helmvalues[imagenamereplace]; ok && v != "" {
					continue
				}

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

				(*imagesvalues)[imagenamereplace] = imagetag

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
			imagesvaluestext += string(bb)
		}
	}

	return imagesvalueslist, imagesvaluestext, nil
}

func TgSetWebhook(url string, allowedupdates []string, secrettoken string) error {
	if DEBUG {
		log("DEBUG TgSetWebhook url==%s allowedupdates==%s secrettoken==%s", url, allowedupdates, secrettoken)
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

func tglog(chatid int64, replyid int64, editid int64, msg string, args ...interface{}) (msgid int64, err error) {
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

	var reqjs []byte
	var tgurl string

	if editid == 0 {
		tgurl = fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", TgToken)
		smreq := TgSendMessageRequest{
			ChatId:              chatid,
			ReplyToMessageId:    replyid,
			Text:                text,
			ParseMode:           TgParseMode,
			DisableNotification: TgDisableNotification,
		}
		reqjs, err = json.Marshal(smreq)
		if err != nil {
			return 0, err
		}
	} else {
		tgurl = fmt.Sprintf("https://api.telegram.org/bot%s/editMessageText", TgToken)
		emreq := TgEditMessageRequest{
			TgSendMessageRequest: TgSendMessageRequest{
				ChatId:              chatid,
				ReplyToMessageId:    replyid,
				Text:                text,
				ParseMode:           TgParseMode,
				DisableNotification: TgDisableNotification,
			},
			MessageId: editid,
		}
		reqjs, err = json.Marshal(emreq)
		if err != nil {
			return 0, err
		}
	}
	reqjsBuffer := bytes.NewBuffer(reqjs)

	var resp *http.Response
	resp, err = http.Post(
		tgurl,
		"application/json",
		reqjsBuffer,
	)
	if err != nil {
		return 0, fmt.Errorf("url==%v data==%v error: %v", tgurl, reqjs, err)
	}

	var smresp TgSendMessageResponse
	err = json.NewDecoder(resp.Body).Decode(&smresp)
	if err != nil {
		return 0, fmt.Errorf("%v", err)
	}
	if !smresp.OK {
		return 0, fmt.Errorf("apiurl==%v apidata==%v api response not ok: %+v", tgurl, reqjs, smresp)
	}

	return smresp.Result.MessageId, nil
}

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

type TgEditMessageRequest struct {
	TgSendMessageRequest
	MessageId int64 `json:"message_id"`
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
