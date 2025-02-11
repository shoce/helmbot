/*

GoGet
GoFmt
GoBuildNull

*/

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
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

	PackagesConfigFilename  string
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

	PackagesConfigFilename = os.Getenv("PackagesConfigFilename")
	if PackagesConfigFilename == "" {
		log("WARNING empty PackagesConfigFilename env var")
	}

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
	if TgWebhookUrl == "" {
		log("WARNING empty TgWebhookUrl env var")
	}

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
		log("TgWebhookUrl==`%s` so setting webhook with telegram to receive updates.", TgWebhookUrl)
		if err := TgSetWebhook(TgWebhookUrl, []string{"message", "channel_post"}, TgWebhookToken); err != nil {
			log("ERROR TgSetWebhook: %+v", err)
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
		log("TgWebhookUrl is not set so this instance will not register telegram webhook.")
	}

	if PackagesConfigFilename != "" {
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
		log("PackagesConfigFilename is not set so this instance will not process packages.")
	}

	log("start done.")

	for {
		time.Sleep(11 * time.Second)
	}

}

func Webhook(w http.ResponseWriter, r *http.Request) {
	var err error
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
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*Your request to force update %s is NOT accepted.*"+NL+NL+"Check helmbot TgBossUserIds config value.",
		); err != nil {
			log("ERROR webhook tglog: %v", err)
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
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*INTERNAL ERROR*"+NL+
				TgAdminMention,
		); err != nil {
			log("ERROR webhook tglog: %v", err)
		}
		return
	}

	log("webhook deployed values hash: %s", ValuesDeployedHash)
	if UpdateValuesHash == ValuesDeployedHash {
		log("DEBUG webhook latest and deployed values hashes match")
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*THIS UPDATE IS ALREADY DEPLOYED*",
		); err != nil {
			log("ERROR webhook tglog: %v", err)
		}
		return
	}

	var ValuesReportedHash string
	if err := GetValuesText(p.ValuesReportedHashFilename(), &ValuesReportedHash); err != nil {
		log("ERROR webhook %v could not be read: %v", p.ValuesReportedHashFilename(), err)
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*INTERNAL ERROR*"+NL+
				TgAdminMention,
		); err != nil {
			log("ERROR webhook tglog: %v", err)
		}
		return
	}

	log("DEBUG webhook reported values hash: %s", ValuesReportedHash)
	if UpdateValuesHash != ValuesReportedHash {
		log("DEBUG webhook latest and reported values hashes mismatch")
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*THIS IS NOT THE LAST AVAILABLE UPDATE*"+NL+NL+"Only the last available update can be forced.",
		); err != nil {
			log("ERROR webhook tglog: %v", err)
		}
		return
	}
	log("DEBUG webhook latest and reported values hashes match")

	log("DEBUG webhook all checks passed")

	log("DEBUG webhook creating %v file", p.ValuesPermitHashFilename())

	if err := PutValuesText(p.ValuesPermitHashFilename(), UpdateValuesHash); err != nil {
		log("ERROR webhook %v file could not be written: %v", p.ValuesPermitHashFilename(), err)
		if err := tglog(
			rupdate.Message.Chat.Id, rupdate.Message.MessageId,
			"*INTERNAL ERROR*"+NL+
				TgAdminMention,
		); err != nil {
			log("ERROR webhook tglog: %v", err)
		}
		return
	}

	log("DEBUG webhook created %v file", p.ValuesPermitHashFilename())

	if err := tglog(
		rupdate.Message.Chat.Id, rupdate.Message.MessageId,
		"*FORCE UPDATE NOW IS ACCEPTED.*"+
			NL+NL+
			"THIS UPDATE WILL START IN FEW MINUTES."+
			NL+NL+
			"`%s`",
		UpdateHashId,
	); err != nil {
		log("ERROR webhook tglog: %v", err)
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

	if err := GetValuesFile(PackagesConfigFilename, nil, &Config); err != nil {
		log("ERROR packages GetValues: %v", err)
		return err
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
			log("DEBUG packages Status==%s Name==%s Namespace==%s Version==%d Chart.Version==%s",
				r.Info.Status, r.Name, r.Namespace, r.Version, r.Chart.Metadata.Version,
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
		if err := GetValuesTextFile(path.Join(p.Dir(), "paused"), &pkgpaused); err == nil {
			// paused package update - skip with no error
			log("DEBUG packages --- Name==%s update paused", p.Name)
			continue
		}

		updatetimestampfilename := path.Join(ConfigDir, p.UpdateTimestampFilename())
		if updatetimestampfilestat, err := os.Stat(updatetimestampfilename); err == nil {
			p.UpdateTimestamp = updatetimestampfilestat.ModTime()
		}

		// TODO do local ops though
		if d := time.Now().Sub(p.UpdateTimestamp).Truncate(time.Second); d < p.UpdateIntervalDuration {
			log("DEBUG packages --- Name=%s %v until next update", p.Name, p.UpdateIntervalDuration-d)
			continue
		}

		timenowhour := fmt.Sprintf("%02d", time.Now().In(p.TimezoneLocation).Hour())

		log("DEBUG packages --- Name==%s Namespace:%s AlwaysForceNow==%v AllowedHours==%v TimeNowHour==%v UpdateInterval==%v", p.Name, p.Namespace, *p.AlwaysForceNow, p.AllowedHoursList, timenowhour, p.UpdateIntervalDuration)

		//
		// READ LATEST VALUES
		//

		err = GetValuesFile(p.GlobalValuesFilename(), &p.GlobalValuesText, p.GlobalValues)
		if err != nil {
			return fmt.Errorf("GetValuesFile %v: %w", p.GlobalValuesFilename(), err)
		}

		err = GetValuesFile(p.ValuesFilename(), &p.ValuesText, p.Values)
		if err != nil {
			return fmt.Errorf("GetValuesFile %v: %w", p.ValuesFilename(), err)
		}

		err = GetValuesFile(p.EnvValuesFilename(), &p.EnvValuesText, p.EnvValues)
		if err != nil {
			return fmt.Errorf("GetValuesFile %v: %w", p.EnvValuesFilename(), err)
		}

		if DEBUG {
			log("DEBUG packages "+SPAC+"config==%#v", p)
			log("DEBUG packages "+SPAC+"repo.address==%#v chartaddress==%#v chartlocalfilename==%#v", p.ChartRepo.Address, p.ChartAddress, p.ChartLocalFilename)
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
			log("DEBUG packages "+SPAC+"chart repo index file path==%#v", indexfilepath)

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

			if !helmregistry.IsOCI(p.ChartAddress) {
				log("WARNING packages "+SPAC+"ChartAddress==%v is not OCI", p.ChartAddress)
			}

			hrclient, err := helmregistry.NewClient(helmregistry.ClientOptDebug(true))
			if err != nil {
				log("ERROR packages "+SPAC+"helmregistry.NewClient: %v", err)
				return err
			}

			chartaddress := strings.TrimPrefix(p.ChartAddress, "oci://")
			tags, err := hrclient.Tags(chartaddress)
			if err != nil {
				log("ERROR packages "+SPAC+"hrclient.Tags: %v", err)
				continue
			}

			if len(tags) == 0 {
				log("WARNING packages "+SPAC+"empty tags list", err)
				continue
			}

			log("DEBUG packages "+SPAC+"tags==%+v", tags)

			chartversion = tags[0]

			if u, err := url.Parse(p.ChartAddress); err != nil {
				log("WARNING packages "+SPAC+"parse ChartAddress: %s", err)
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
				log("ERROR packages "+SPAC+"ChartLocalFilename==%v is not a .tgz file", p.ChartLocalFilename)
				continue
			}

			if mm, err := filepath.Glob(path.Join(ConfigDir, p.ChartLocalFilename)); err != nil {
				log("ERROR packages "+SPAC+"Glob ConfigDir==%v ChartLocalFilename==%v: %s", ConfigDir, p.ChartLocalFilename, err)
				continue
			} else if len(mm) == 0 {
				log("ERROR packages "+SPAC+"Glob ConfigDir==%v ChartLocalFilename==%v files not found", ConfigDir, p.ChartLocalFilename)
				continue
			} else {
				sort.Sort(sort.Reverse(sort.StringSlice(mm)))
				chartpath = mm[0]
			}

		} else {

			log("ERROR package %s has no ChartRepoAddress, ChartAddress, ChartLocalFilename", p.Name)
			continue

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

		tnow := time.Now()
		if err := os.Chtimes(updatetimestampfilename, tnow, tnow); os.IsNotExist(err) {
			if f, err := os.Create(updatetimestampfilename); err == nil {
				f.Close()
			} else {
				log("ERROR packages "+SPAC+"create timestamp file: %s", err)
			}
		}

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
		// LATEST VALUES HASH
		//

		allvaluestext := p.GlobalValuesText + p.ValuesText + p.EnvValuesText + p.ImagesValuesText
		p.ValuesHash = fmt.Sprintf("%x", sha256.Sum256([]byte(allvaluestext)))[:10]

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

		// READ DEPLOYED HASH

		var ValuesDeployedHash string
		if err := GetValuesTextFile(p.ValuesDeployedHashFilename(), &ValuesDeployedHash); err != nil {
			log("ERROR packages "+SPAC+"GetValuesTextFile: %s", err)
		}

		// COMPARE LATEST VS DEPLOYED

		if p.GlobalValuesText != DeployedGlobalValuesText {
			log("DEBUG packages " + SPAC + "GlobalValuesText diff ")
		}

		if p.ValuesText != DeployedValuesText {
			log("DEBUG packages " + SPAC + "ValuesText diff ")
		}

		if p.EnvValuesText != DeployedEnvValuesText {
			log("DEBUG packages " + SPAC + "EnvValuesText diff ")
		}

		imagesvaluesdiff := ""

		if p.ImagesValuesText != DeployedImagesValuesText {

			log("DEBUG packages " + SPAC + "ImagesValuesText diff ")

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
						imagesvaluesdiff += fmt.Sprintf("%s: %#v => %#v "+NL, name, v1, v2)
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

		// READ REPORTED HASH

		var ValuesReportedHash string
		if err := GetValuesTextFile(p.ValuesReportedHashFilename(), &ValuesReportedHash); err != nil {
			log("ERROR packages "+SPAC+"GetValuesTextFile: %s", err)
		}

		// READ PERMIT HASH

		var PermitHash string
		if err := GetValuesTextFile(p.ValuesPermitHashFilename(), &PermitHash); err != nil {
			log("ERROR packages "+SPAC+"GetValuesTextFile: %s", err)
		}

		if p.ValuesHash != ValuesReportedHash {

			//
			// WRITE LATEST
			//

			err = os.RemoveAll(path.Join(ConfigDir, p.LatestDir()))
			if err != nil {
				return fmt.Errorf("os.RemoveAll %v: %w", path.Join(ConfigDir, p.LatestDir()), err)
			}

			err = os.MkdirAll(path.Join(ConfigDir, p.LatestDir()), 0700)
			if err != nil {
				return fmt.Errorf("os.MkdirAll %v: %w", path.Join(ConfigDir, p.LatestDir()), err)
			}

			if err := PutValuesTextFile(path.Join(p.LatestDir(), p.GlobalValuesFilename()), p.GlobalValuesText); err != nil {
				return fmt.Errorf("PutValuesTextFile: %w", err)
			}

			if err := PutValuesTextFile(path.Join(p.LatestDir(), p.ValuesFilename()), p.ValuesText); err != nil {
				return fmt.Errorf("PutValuesTextFile: %w", err)
			}

			if err := PutValuesTextFile(path.Join(p.LatestDir(), p.EnvValuesFilename()), p.EnvValuesText); err != nil {
				return fmt.Errorf("PutValuesTextFile: %w", err)
			}

			if err := PutValuesTextFile(path.Join(p.LatestDir(), p.ImagesValuesFilename()), p.ImagesValuesText); err != nil {
				return fmt.Errorf("PutValuesTextFile: %w", err)
			}

			if err := PutValuesTextFile(p.ValuesLatestHashFilename(), p.ValuesHash); err != nil {
				return fmt.Errorf("PutValuesTextFile: %w", err)
			}

			log("DEBUG packages "+SPAC+"%s latest ", p.HashId())

			//
			// LATEST => REPORTED
			//

			if err := os.RemoveAll(path.Join(ConfigDir, p.ReportedDir())); err != nil {
				return fmt.Errorf("os.RemoveAll %v: %w", p.ReportedDir(), err)
			}

			if err := os.Rename(path.Join(ConfigDir, p.LatestDir()), path.Join(ConfigDir, p.ReportedDir())); err != nil {
				return fmt.Errorf("os.Rename %v %v: %w", path.Join(ConfigDir, p.LatestDir()), path.Join(ConfigDir, p.ReportedDir()), err)
			}

			ValuesReportedHash = p.ValuesHash

			if err := PutValuesTextFile(p.ValuesReportedHashFilename(), ValuesReportedHash); err != nil {
				return fmt.Errorf("PutValuesTextFile: %w", err)
			}

			// TODO report pending update to telegram

			tgmsg := fmt.Sprintf("*%s %s %s UPDATE*", strings.ToUpper(ServerHostname), strings.ToUpper(p.ChartName), strings.ToUpper(p.EnvName)) + NL + NL
			if p.GlobalValuesText != DeployedGlobalValuesText {
				tgmsg += fmt.Sprintf("`%s` changed", p.GlobalValuesFilename()) + NL + NL
			}
			if p.ValuesText != DeployedValuesText {
				tgmsg += fmt.Sprintf("`%s` changed", p.ValuesFilename()) + NL + NL
			}
			if p.EnvValuesText != DeployedEnvValuesText {
				tgmsg += fmt.Sprintf("`%s` changed", p.EnvValuesFilename()) + NL + NL
			}
			if imagesvaluesdiff != "" {
				tgmsg += fmt.Sprintf("`%s` diff:"+NL+NL+"```"+NL+"%s"+NL+"```", p.ImagesValuesFilename(), imagesvaluesdiff) + NL + NL
			}
			tgmsg += fmt.Sprintf("`%s`", p.HashId()) + NL

			if err := tglog(TgBossUserIds[0], 0, tgmsg); err != nil {
				log("ERROR packages tglog: %v", err)
			}

			log("DEBUG packages "+SPAC+"%s reported ", p.HashId())

		}

		log("DEBUG packages "+SPAC+"ValuesHash==%v ValuesReportedHash==%v ValuesDeployedHash==%v PermitHash==%v ", p.ValuesHash, ValuesReportedHash, ValuesDeployedHash, PermitHash)

		todeploy := false

		if ValuesReportedHash != ValuesDeployedHash {

			if PermitHash == ValuesReportedHash {
				todeploy = true
			}

			if p.AlwaysForceNow != nil && *p.AlwaysForceNow {
				todeploy = true
			}

			if len(p.AllowedHoursList) > 0 && todeploy == false {
				log("DEBUG packages "+SPAC+"AllowedHoursList==%+v timenowhour==%+v", p.AllowedHoursList, timenowhour)
			}

			if slices.Contains(p.AllowedHoursList, timenowhour) {
				todeploy = true
			}

		}

		log("DEBUG packages "+SPAC+"todeploy==%v", todeploy)

		if todeploy {

			// TODO report starting update to telegram

			tgmsg := fmt.Sprintf("*%s %s %s UPDATE*", strings.ToUpper(ServerHostname), strings.ToUpper(p.ChartName), strings.ToUpper(p.EnvName)) + NL + NL
			tgmsg += fmt.Sprintf("*STARTING IN %v*", p.UpdateDelayDuration) + NL
			tgmsg += fmt.Sprintf("`%s`", p.HashId()) + NL

			if err := tglog(TgBossUserIds[0], 0, tgmsg); err != nil {
				log("ERROR packages tglog: %v", err)
			}

			if p.UpdateDelayDuration > 0 {
				log("DEBUG packages "+SPAC+"sleeping %v", p.UpdateDelayDuration)
				time.Sleep(p.UpdateDelayDuration)
			}

			//
			// DEPLOY
			//

			namespaceexists := false
			if kns, err := kclientset.CoreV1().Namespaces().Get(context.TODO(), p.Namespace, kmetav1.GetOptions{}); kerrors.IsNotFound(err) {
				// namespaceexists == false
			} else if err != nil {
				log("ERROR packages Namespaces.Get: %v", err)
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

			// VALUES

			values := make(map[string]interface{})
			helmchartutil.MergeTables(values, p.ImagesValues)
			helmchartutil.MergeTables(values, p.EnvValues)
			helmchartutil.MergeTables(values, p.Values)
			helmchartutil.MergeTables(values, p.GlobalValues)
			helmchartutil.MergeTables(values, chartfull.Values)

			log("DEBUG packages "+SPAC+"values==%+v", values)

			if err := helmactioncfg.Init(helmenvsettings.RESTClientGetter(), p.Namespace, "", log); err != nil {
				return err
			}

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
					return err
				}

			}

			err = os.RemoveAll(path.Join(ConfigDir, p.DeployedDir()))
			if err != nil {
				return fmt.Errorf("os.RemoveAll %v: %w", path.Join(ConfigDir, p.DeployedDir()), err)
			}

			err = os.Rename(path.Join(ConfigDir, p.ReportedDir()), path.Join(ConfigDir, p.DeployedDir()))
			if err != nil {
				return fmt.Errorf("os.Rename %v %v: %w", path.Join(ConfigDir, p.ReportedDir()), path.Join(ConfigDir, p.DeployedDir()), err)
			}

			if err := PutValuesTextFile(p.ValuesDeployedHashFilename(), ValuesReportedHash); err != nil {
				return fmt.Errorf("PutValuesTextFile: %w", err)
			}

			// TODO remove p.ValuesPermitHashFilename()

			log("DEBUG packages "+SPAC+"%s deployed ", p.HashId())

			log("DEBUG packages "+SPAC+"release Name==%v Namespace==%v Version==%v Info.Status==%v", release.Name, release.Namespace, release.Version, release.Info.Status)

			// TODO report finished update to telegram

			tgmsg = fmt.Sprintf("*%s %s %s UPDATE FINISHED*", strings.ToUpper(ServerHostname), strings.ToUpper(p.ChartName), strings.ToUpper(p.EnvName)) + NL + NL
			tgmsg += fmt.Sprintf("`%s`", p.HashId()) + NL

			if err := tglog(TgBossUserIds[0], 0, tgmsg); err != nil {
				log("ERROR packages tglog: %v", err)
			}

		}

		time.Sleep(1 * time.Second)

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

		for _, p := range s.Packages {

			p.Name = fmt.Sprintf("%s-%s", p.ChartName, p.EnvName)

			if p.Namespace == "" {
				p.Namespace = fmt.Sprintf("%s-%s", p.ChartName, p.EnvName)
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

			if p.TgChatId == nil {
				p.TgChatId = s.TgChatId
			}
			if p.TgMentions == nil {
				p.TgMentions = s.TgMentions
			}

			if p.DryRun == nil {
				if s.DryRun == nil {
					varfalse := false
					p.DryRun = &varfalse
				} else {
					p.DryRun = s.DryRun
				}
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
	Name      string `yaml:"Name"`
	Namespace string `yaml:"Namespace,omitempty"`
	ChartName string `yaml:"ChartName"`
	EnvName   string `yaml:"EnvName"`

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

func (p *PackageConfig) Dir() string {
	return p.Name
}
func (p *PackageConfig) LatestDir() string {
	return path.Join(p.Dir(), "latest")
}
func (p *PackageConfig) ReportedDir() string {
	return path.Join(p.Dir(), "reported")
}
func (p *PackageConfig) DeployedDir() string {
	return path.Join(p.Dir(), "deployed")
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

type ServerConfig struct {
	ServerHostname string `yaml:"ServerHostname"`

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
